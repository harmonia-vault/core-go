package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

var (
	ErrWriteInput      = errors.New("invalid explicit shared write")
	ErrWriteConflict   = errors.New("shared request identifier already binds another input")
	ErrWritePermission = errors.New("current environment does not permit shared writing")
	ErrWritePending    = errors.New("shared write result pending; query the same request identifier")
	ErrWriteJournal    = errors.New("protected shared write journal failed")
)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// WriteJournal 只能由唯一后台owner提供加密持久存储；不保存原始输入值。
type WriteJournal interface {
	Load() ([]byte, error)
	Save([]byte) error
}
type WriteRequest struct {
	ID, Operation, EnvironmentID, Name, Value string
	Values                                    map[string]string
}
type WriteResult struct {
	RequestID string   `json:"requestId"`
	Total     int      `json:"total"`
	Accepted  int      `json:"accepted"`
	Applied   bool     `json:"applied"`
	Sequences []uint64 `json:"sequences"`
}
type MutationStatus struct {
	IdempotencyKey string `json:"idempotencyKey"`
	Accepted       bool   `json:"accepted"`
	Sequence       uint64 `json:"sequence,omitempty"`
	ContentHash    string `json:"contentHash,omitempty"`
}
type writeItem struct {
	ContentHash string         `json:"contentHash"`
	Mutation    SignedMutation `json:"mutation"`
	Sequence    uint64         `json:"sequence,omitempty"`
}
type writeRecord struct {
	Canceled     bool        `json:"canceled,omitempty"`
	RequestID    string      `json:"requestId"`
	InputHash    string      `json:"inputHash"`
	BaseSequence uint64      `json:"baseSequence"`
	Items        []writeItem `json:"items"`
	Applied      bool        `json:"applied"`
}
type writeLog struct {
	SessionEpoch      uint64        `json:"sessionEpoch"`
	Version           int           `json:"version"`
	AccountID         string        `json:"accountId"`
	AccountGeneration uint64        `json:"accountGeneration"`
	DeviceID          string        `json:"deviceId"`
	Records           []writeRecord `json:"records"`
}
type Writer struct {
	closed  bool
	mu      sync.Mutex
	key     ed25519.PrivateKey
	journal WriteJournal
	log     writeLog
}

func NewWriter(accountID string, generation uint64, deviceID string, epoch uint64, key ed25519.PrivateKey, journal WriteJournal) (*Writer, error) {
	if !enrollmentID.MatchString(accountID) || generation == 0 || !enrollmentID.MatchString(deviceID) || len(key) != ed25519.PrivateKeySize || journal == nil {
		return nil, ErrWriteInput
	}
	w := &Writer{key: bytes.Clone(key), journal: journal, log: writeLog{Version: 1, SessionEpoch: epoch, AccountID: accountID, AccountGeneration: generation, DeviceID: deviceID, Records: []writeRecord{}}}
	data, err := journal.Load()
	if errors.Is(err, os.ErrNotExist) {
		return w, nil
	}
	if err != nil {
		w.Close()
		return nil, ErrWriteJournal
	}
	defer clear(data)
	if len(data) > 8<<20 {
		w.Close()
		return nil, ErrWriteJournal
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var saved writeLog
	var extra any
	if decoder.Decode(&saved) != nil || decoder.Decode(&extra) != io.EOF || saved.Version != 1 || saved.AccountID != accountID || saved.AccountGeneration != generation || saved.DeviceID != deviceID || saved.SessionEpoch > epoch || len(saved.Records) > 32 {
		w.Close()
		return nil, ErrWriteJournal
	}
	ids := map[string]bool{}
	for _, r := range saved.Records {
		if !requestIDPattern.MatchString(r.RequestID) || ids[r.RequestID] || !lowerHash(r.InputHash) || len(r.Items) < 1 || len(r.Items) > 16 || r.BaseSequence > 9007199254740991 {
			w.Close()
			return nil, ErrWriteJournal
		}
		ids[r.RequestID] = true
		for i, item := range r.Items {
			m := item.Mutation.Mutation
			if m.AccountID != accountID || m.AccountGeneration != strconv.FormatUint(generation, 10) || m.DeviceID != deviceID || m.IdempotencyKey != r.RequestID+"."+strconv.Itoa(i) || item.Sequence > 9007199254740991 || !lowerHash(item.ContentHash) || !r.Canceled && cryptox.VerifyMutation(cryptox.SignedMutation{Mutation: m, Signature: item.Mutation.Signature}, key.Public().(ed25519.PublicKey)) != nil {
				w.Close()
				return nil, ErrWriteJournal
			}
			if !r.Canceled {
				hash, err := signedContentHash(item.Mutation)
				if err != nil || hash != item.ContentHash {
					w.Close()
					return nil, ErrWriteJournal
				}
			}
		}
	}
	w.log = saved
	if saved.SessionEpoch < epoch {
		// 账号/设备仍相同，但安全epoch已推进。仅取消旧待写密文，不能恢复其提交资格。
		for i := range w.log.Records {
			if !w.log.Records[i].Applied {
				cancelWriteRecord(&w.log.Records[i])
			}
		}
		w.log.SessionEpoch = epoch
		if err = w.save(); err != nil {
			w.Close()
			return nil, err
		}
	}
	return w, nil
}
func lowerHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range value {
		if !strings.ContainsRune("0123456789abcdef", b) {
			return false
		}
	}
	return true
}
func (w *Writer) Close() { w.mu.Lock(); defer w.mu.Unlock(); clear(w.key); w.closed = true }
func (w *Writer) save() error {
	data, err := json.Marshal(w.log)
	if err != nil {
		return ErrWriteJournal
	}
	defer clear(data)
	if len(data) > 8<<20 || w.journal.Save(data) != nil {
		return ErrWriteJournal
	}
	return nil
}
func validSharedValue(name, value string) bool {
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`).MatchString(name) && !strings.HasPrefix(strings.ToUpper(name), "__HARMONIA_") && len(value) <= cryptox.MaxValueBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
func ValidateWriteRequest(r WriteRequest) error {
	if !requestIDPattern.MatchString(r.ID) {
		return ErrWriteInput
	}
	if r.Operation == "retry" {
		if r.EnvironmentID != "" || r.Name != "" || r.Value != "" || len(r.Values) != 0 {
			return ErrWriteInput
		}
		return nil
	}
	if !enrollmentID.MatchString(r.EnvironmentID) {
		return ErrWriteInput
	}
	switch r.Operation {
	case "put":
		if !validSharedValue(r.Name, r.Value) || len(r.Values) != 0 {
			return ErrWriteInput
		}
	case "delete":
		if !validSharedValue(r.Name, "") || r.Value != "" || len(r.Values) != 0 {
			return ErrWriteInput
		}
	case "import":
		if r.Name != "" || r.Value != "" || len(r.Values) < 1 || len(r.Values) > 16 {
			return ErrWriteInput
		}
		size := 0
		for name, value := range r.Values {
			if !validSharedValue(name, value) {
				return ErrWriteInput
			}
			size += len(value)
		}
		if size > cryptox.MaxValueBytes {
			return ErrWriteInput
		}
	default:
		return ErrWriteInput
	}
	return nil
}
func inputFingerprint(log writeLog, r WriteRequest) string {
	names := []string{}
	if r.Operation == "import" {
		for name := range r.Values {
			names = append(names, name)
		}
		sort.Strings(names)
	} else {
		names = []string{r.Name}
	}
	entries := make([][]string, 0, len(names))
	for _, name := range names {
		value := r.Value
		if r.Operation == "import" {
			value = r.Values[name]
		}
		entries = append(entries, []string{name, value})
	}
	data, _ := json.Marshal([]any{"harmonia/local-shared-input/v1", log.AccountID, strconv.FormatUint(log.AccountGeneration, 10), log.DeviceID, r.ID, r.Operation, r.EnvironmentID, entries})
	defer clear(data)
	return digest(data)
}
func signedContentHash(m SignedMutation) (string, error) {
	wire, err := m.Mutation.SigningBytes()
	if err != nil {
		return "", err
	}
	return digest([]byte(cryptox.EncodeBase64(wire) + "." + m.Signature)), nil
}
func (c *Client) MutationStatus(ctx context.Context, id string) (MutationStatus, error) {
	if !enrollmentID.MatchString(id) {
		return MutationStatus{}, ErrWriteInput
	}
	u := c.endpointFor("/mutation-status")
	q := u.Query()
	q.Set("idempotencyKey", id)
	u.RawQuery = q.Encode()
	var status MutationStatus
	if err := c.request(ctx, "GET", u, nil, &status); err != nil {
		return status, err
	}
	if status.IdempotencyKey != id || status.Accepted && (status.Sequence == 0 || status.Sequence > 9007199254740991 || !lowerHash(status.ContentHash)) || !status.Accepted && (status.Sequence != 0 || status.ContentHash != "") {
		return MutationStatus{}, errors.New("unbound mutation receipt")
	}
	return status, nil
}
func (w *Writer) prepare(c *Client, pull Pull, r WriteRequest) (writeRecord, error) {
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || !bytes.Equal(w.key.Public().(ed25519.PublicKey), v.trust.DeviceSigningPublicKey) {
		return writeRecord{}, ErrWritePermission
	}
	var grant *Grant
	for i := range pull.Grants {
		g := &pull.Grants[i].Grant
		if g.EnvironmentID == r.EnvironmentID {
			grant = g
			break
		}
	}
	if grant == nil || grant.Role != "rw" && grant.Role != "admin" {
		return writeRecord{}, ErrWritePermission
	}
	env, exists := c.config.Engine.State().Cloud.Environments[r.EnvironmentID]
	if !exists || env.ExpiresAt != nil && !c.config.Now().Before(*env.ExpiresAt) {
		return writeRecord{}, ErrWritePermission
	}
	packet, err := cryptox.DecodeBase64(grant.Envelope, 80, 80)
	if err != nil {
		return writeRecord{}, ErrWritePermission
	}
	key, err := cryptox.UnwrapEnvironmentKey(v.trust.ReceivingPrivateKey, cryptox.EnvelopeContext{AccountID: grant.AccountID, AccountGeneration: grant.AccountGeneration, EnvironmentID: grant.EnvironmentID, KeyVersion: grant.KeyVersion, RecipientType: "device", RecipientID: grant.SubjectDeviceID, RecipientGeneration: grant.GrantGeneration, RecipientPublicKey: grant.SubjectReceivingPublicKey}, packet)
	if err != nil {
		return writeRecord{}, ErrWritePermission
	}
	defer clear(key)
	names := []string{r.Name}
	if r.Operation == "import" {
		names = nil
		for name := range r.Values {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	record := writeRecord{RequestID: r.ID, InputHash: inputFingerprint(w.log, r), BaseSequence: pull.Sequence, Items: []writeItem{}}
	for i, name := range names {
		op := "put"
		payload := ""
		if r.Operation == "delete" {
			op = "delete"
		} else {
			value := r.Value
			if r.Operation == "import" {
				value = r.Values[name]
			}
			plain := []byte(value)
			cipher, err := cryptox.EncryptValue(key, cryptox.ValueContext{AccountID: w.log.AccountID, AccountGeneration: strconv.FormatUint(w.log.AccountGeneration, 10), EnvironmentID: r.EnvironmentID, KeyVersion: grant.KeyVersion, Name: name}, plain)
			clear(plain)
			if err != nil {
				return writeRecord{}, ErrWriteInput
			}
			payload = cryptox.EncodeBase64(cipher)
		}
		m, err := cryptox.SignMutation(cryptox.Mutation{AccountID: w.log.AccountID, AccountGeneration: strconv.FormatUint(w.log.AccountGeneration, 10), DeviceID: w.log.DeviceID, EnvironmentID: r.EnvironmentID, KeyVersion: grant.KeyVersion, GrantGeneration: grant.GrantGeneration, Operation: op, IdempotencyKey: r.ID + "." + strconv.Itoa(i), Name: name, Payload: payload}, w.key)
		if err != nil {
			return writeRecord{}, ErrWriteInput
		}
		signed := SignedMutation{Mutation: m.Mutation, Signature: m.Signature}
		hash, _ := signedContentHash(signed)
		record.Items = append(record.Items, writeItem{Mutation: signed, ContentHash: hash})
	}
	return record, nil
}
func recordResult(r writeRecord) WriteResult {
	result := WriteResult{RequestID: r.RequestID, Total: len(r.Items), Applied: r.Applied, Sequences: make([]uint64, len(r.Items))}
	for i, item := range r.Items {
		result.Sequences[i] = item.Sequence
		if item.Sequence > 0 {
			result.Accepted++
		}
	}
	return result
}

// Execute 由唯一owner串行调用。预拉与最终拉取都是原验签流；没有本地乐观写入。
// Mutation协议是服务器接受次序LWW，不添加expectedSequence/CAS字段。
func (w *Writer) Execute(ctx context.Context, c *Client, r WriteRequest) (WriteResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ValidateWriteRequest(r); err != nil {
		return WriteResult{}, err
	}
	if w.closed || len(w.key) != ed25519.PrivateKeySize || c == nil || c.config.AccountID != w.log.AccountID || c.config.AccountGeneration != w.log.AccountGeneration || c.config.DeviceID != w.log.DeviceID || c.epoch != w.log.SessionEpoch {
		return WriteResult{}, ErrWritePermission
	}
	if c.config.Engine.State().Paused {
		return WriteResult{RequestID: r.ID}, ErrPaused
	}
	index := -1
	for i := range w.log.Records {
		if w.log.Records[i].RequestID == r.ID {
			index = i
			break
		}
	}
	if index >= 0 && w.log.Records[index].Canceled {
		record := &w.log.Records[index]
		for i := range record.Items {
			item := &record.Items[i]
			status, err := c.MutationStatus(ctx, item.Mutation.Mutation.IdempotencyKey)
			if err != nil {
				return recordResult(*record), errors.Join(ErrWritePending, err)
			}
			if status.Accepted {
				if status.ContentHash != item.ContentHash || item.Sequence != 0 && item.Sequence != status.Sequence {
					return recordResult(*record), ErrWriteConflict
				}
				item.Sequence = status.Sequence
			}
		}
		if err := w.save(); err != nil {
			return recordResult(*record), err
		}
		return recordResult(*record), ErrWritePermission
	}
	if index >= 0 && r.Operation != "retry" && w.log.Records[index].InputHash != inputFingerprint(w.log, r) {
		return recordResult(w.log.Records[index]), ErrWriteConflict
	}
	if index < 0 && r.Operation == "retry" {
		return WriteResult{RequestID: r.ID}, ErrWriteInput
	}
	pull, err := c.Pull(ctx)
	if err != nil {
		return WriteResult{RequestID: r.ID}, err
	}
	if index < 0 {
		record, err := w.prepare(c, pull, r)
		if err != nil {
			return WriteResult{RequestID: r.ID}, err
		}
		if len(w.log.Records) >= 32 {
			remove := -1
			for i, r := range w.log.Records {
				if r.Applied || r.Canceled {
					remove = i
					break
				}
			}
			if remove < 0 {
				return WriteResult{RequestID: r.ID}, ErrWriteJournal
			}
			w.log.Records = append(w.log.Records[:remove], w.log.Records[remove+1:]...)
		}
		w.log.Records = append(w.log.Records, record)
		index = len(w.log.Records) - 1
		if err = w.save(); err != nil {
			return recordResult(record), err
		}
	}
	record := &w.log.Records[index]
	record.Applied = false
	if err = w.save(); err != nil {
		return recordResult(*record), err
	}
	for i := range record.Items {
		item := &record.Items[i]
		status, err := c.MutationStatus(ctx, item.Mutation.Mutation.IdempotencyKey)
		if err != nil {
			return recordResult(*record), errors.Join(ErrWritePending, err)
		}
		if status.Accepted {
			if status.ContentHash != item.ContentHash || item.Sequence != 0 && item.Sequence != status.Sequence {
				return recordResult(*record), ErrWriteConflict
			}
			item.Sequence = status.Sequence
			if err = w.save(); err != nil {
				return recordResult(*record), err
			}
			continue
		}
		if item.Sequence != 0 {
			return recordResult(*record), ErrWriteConflict
		}
		// 已接受项可查历史收据；未接受项仍要求当前有效RW/Admin和相同版本/授权。
		env, ok := c.config.Engine.State().Cloud.Environments[item.Mutation.Mutation.EnvironmentID]
		m := item.Mutation.Mutation
		version, _ := strconv.ParseUint(m.KeyVersion, 10, 64)
		generation, _ := strconv.ParseUint(m.GrantGeneration, 10, 64)
		if !ok || env.Role != localstate.ReadWrite && env.Role != localstate.Admin || env.KeyVersion != version || env.GrantGeneration != generation || env.ExpiresAt != nil && !c.config.Now().Before(*env.ExpiresAt) {
			cancelWriteRecord(record)
			if err = w.save(); err != nil {
				return recordResult(*record), err
			}
			return recordResult(*record), ErrWritePermission
		}
		result, err := c.Submit(ctx, item.Mutation)
		if result.Accepted.Sequence > 0 {
			if result.Accepted.Sequence <= record.BaseSequence {
				return recordResult(*record), ErrWriteConflict
			}
			item.Sequence = result.Accepted.Sequence
			if saveErr := w.save(); saveErr != nil {
				return recordResult(*record), saveErr
			}
		}
		if err != nil {
			var fault *RequestError
			if errors.As(err, &fault) && fault.Status == 403 && (fault.Code == "write_forbidden" || fault.Code == "grant_stale" || fault.Code == "permission_denied" || fault.Code == "environment_unavailable" || fault.Code == "environment_forbidden" || fault.Code == "key_version_stale") {
				_, refreshErr := c.RefreshAuthorizations(ctx)
				cancelWriteRecord(record)
				if saveErr := w.save(); saveErr != nil {
					return recordResult(*record), saveErr
				}
				return recordResult(*record), errors.Join(ErrWritePermission, err, refreshErr)
			}
			return recordResult(*record), errors.Join(ErrWritePending, err)
		}
	}
	if _, err = c.Pull(ctx); err != nil {
		return recordResult(*record), errors.Join(ErrWritePending, err)
	}
	snapshot := c.config.Engine.State().Cloud
	for _, item := range record.Items {
		m := item.Mutation.Mutation
		env, readable := snapshot.Environments[m.EnvironmentID]
		version, _ := strconv.ParseUint(m.KeyVersion, 10, 64)
		if !readable || env.KeyVersion != version {
			cancelWriteRecord(record)
			if err = w.save(); err != nil {
				return recordResult(*record), err
			}
			return recordResult(*record), ErrWritePermission
		}
		seen, exists := snapshot.SeenMutations[m.DeviceID+"/"+m.IdempotencyKey]
		wire, _ := m.SigningBytes()
		if !exists || seen.Sequence != item.Sequence || seen.Fingerprint != digest(wire) {
			return recordResult(*record), ErrWritePending
		}
		if snapshot.Sequence < item.Sequence {
			return recordResult(*record), ErrWritePending
		}
	}
	record.Applied = true
	if err = w.save(); err != nil {
		return recordResult(*record), err
	}
	return recordResult(*record), nil
}

func cancelWriteRecord(record *writeRecord) {
	record.Canceled = true
	record.Applied = false
	for i := range record.Items {
		record.Items[i].Mutation.Mutation.Payload = ""
		record.Items[i].Mutation.Signature = ""
	}
}

// CancelPending 用于已验证的全部授权失效；保存ID墓碑而清待提交密文。
func (w *Writer) CancelPending(epoch uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriteJournal
	}
	for i := range w.log.Records {
		if !w.log.Records[i].Applied {
			cancelWriteRecord(&w.log.Records[i])
		}
	}
	w.log.SessionEpoch = epoch
	return w.save()
}

// PruneUnavailable 在已验签的授权变化之后清失权/旧版本待写密文，不自动上传。
func (w *Writer) PruneUnavailable(snapshot localstate.CloudSnapshot) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWriteJournal
	}
	changed := false
	for i := range w.log.Records {
		r := &w.log.Records[i]
		if r.Applied || r.Canceled {
			continue
		}
		for _, item := range r.Items {
			m := item.Mutation.Mutation
			env, exists := snapshot.Environments[m.EnvironmentID]
			version, _ := strconv.ParseUint(m.KeyVersion, 10, 64)
			generation, _ := strconv.ParseUint(m.GrantGeneration, 10, 64)
			if !exists || env.Role != localstate.ReadWrite && env.Role != localstate.Admin || env.KeyVersion != version || env.GrantGeneration != generation {
				cancelWriteRecord(r)
				changed = true
				break
			}
		}
	}
	if changed {
		return w.save()
	}
	return nil
}
