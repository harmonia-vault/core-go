package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// GrantStatus 只含本设备原授权操作的接受元数据，不返回封套或目录公钥。
type GrantStatus struct {
	IdempotencyKey string `json:"idempotencyKey"`
	Accepted       bool   `json:"accepted"`
	Sequence       uint64 `json:"sequence,omitempty"`
	ContentHash    string `json:"contentHash,omitempty"`
}

// GrantContentHash 与服务器持久化 content 完全相同，禁止以当前同名权限猜测原操作成功。
func GrantContentHash(s cryptox.SignedGrantWire) (string, error) {
	wire, e := s.Grant.SigningBytes()
	if e != nil {
		return "", e
	}
	if _, e = cryptox.DecodeBase64(s.Signature, 64, 64); e != nil {
		return "", e
	}
	digest := sha256.Sum256([]byte(cryptox.EncodeBase64(wire) + "." + s.Signature))
	return hex.EncodeToString(digest[:]), nil
}

func (c *Client) GrantStatus(ctx context.Context, id string) (GrantStatus, error) {
	var result GrantStatus
	if !enrollmentID.MatchString(id) || len(id) > 64 {
		return result, cryptox.ErrInvalidWire
	}
	target := c.endpointFor("/grant-status")
	query := url.Values{}
	query.Set("idempotencyKey", id)
	target.RawQuery = query.Encode()
	if e := c.request(ctx, "GET", target, nil, &result); e != nil {
		return result, e
	}
	if result.IdempotencyKey != id {
		return GrantStatus{}, cryptox.ErrInvalidWire
	}
	if !result.Accepted {
		if result.Sequence != 0 || result.ContentHash != "" {
			return GrantStatus{}, cryptox.ErrInvalidWire
		}
	} else if result.Sequence == 0 || result.Sequence > 9007199254740991 || !lowerHash(result.ContentHash) {
		return GrantStatus{}, cryptox.ErrInvalidWire
	}
	return result, nil
}

// grantIdentity 仅是已签操作的本地 tuple 校验；不授予任何管理权限。
func (c *Client) grantIdentity(s cryptox.SignedGrantWire) error {
	g := s.Grant
	if g.AccountID != c.config.AccountID || g.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || g.IssuerDeviceID != c.config.DeviceID {
		return cryptox.ErrInvalidWire
	}
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil {
		return ErrWritePermission
	}
	return cryptox.VerifyGrant(s.SignedGrant(), v.trust.DeviceSigningPublicKey)
}

// ManagementSubject 的公钥只在已验身份图内匹配后才可用于重新封装。
// CurrentGrant 可是 none/到期/旧KV；这些历史状态不授予当前管理权。
type ManagementSubject struct {
	DeviceID               string                   `json:"deviceId"`
	SigningPublicKey       string                   `json:"signingPublicKey"`
	ReceivingPublicKey     string                   `json:"receivingPublicKey"`
	CurrentGrant           *cryptox.SignedGrantWire `json:"currentGrant"`
	HighestGrantGeneration string                   `json:"highestGrantGeneration"`
}
type ManagementControl struct {
	AccountID              string                       `json:"accountId"`
	AccountGeneration      string                       `json:"accountGeneration"`
	EnvironmentID          string                       `json:"environmentId"`
	Sequence               uint64                       `json:"sequence"`
	KeyVersion             string                       `json:"keyVersion"`
	Subjects               []ManagementSubject          `json:"subjects"`
	IssuerEvidence         cryptox.IssuerProofV2        `json:"issuerEvidence"`
	IssuerRecoveryEvidence *cryptox.IssuerRecoveryProof `json:"issuerRecoveryEvidence,omitempty"`
}

func (c *Client) verifyManagementControl(out ManagementControl, historical ...bool) (VerifiedControlEvidence, cryptox.SignedGrantWire, error) {
	var own cryptox.SignedGrantWire
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || v.evidenceRoot == nil || c.config.Engine.State().SessionEpoch != c.epoch || c.config.Engine.State().AccountClosed {
		return nil, own, ErrWritePermission
	}
	state := c.config.Engine.State()
	if out.AccountID != c.config.AccountID || out.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || !enrollmentID.MatchString(out.EnvironmentID) || (len(historical) == 0 && (out.Sequence < state.Cloud.Sequence || out.Sequence < state.Cloud.AuthorizationSequence)) || out.Sequence > 9007199254740991 || len(out.Subjects) < 1 || len(out.Subjects) > 256 {
		return nil, own, cryptox.ErrInvalidWire
	}
	version, e := parsePositive(out.KeyVersion)
	if e != nil {
		return nil, own, e
	}
	proof, e := c.verifyControlEvidence(out.IssuerEvidence, out.IssuerRecoveryEvidence, out.Sequence, len(historical) > 0)
	if e != nil {
		return nil, own, e
	}
	// 身份来自完整受签来源，不从服务端目录第一次绑定。
	identities := map[string]ManagementSubject{}
	for _, binding := range proof.IssuerBindings() {
		if previous, exists := identities[binding.DeviceID]; exists && (previous.SigningPublicKey != binding.SigningPublicKey || previous.ReceivingPublicKey != binding.ReceivingPublicKey) {
			return nil, own, cryptox.ErrInvalidWire
		}
		identities[binding.DeviceID] = ManagementSubject{DeviceID: binding.DeviceID, SigningPublicKey: binding.SigningPublicKey, ReceivingPublicKey: binding.ReceivingPublicKey}
	}
	// Proof3 的已归档设备可以尚未获本环境授权；权源枚举不等于完整身份集合。
	// 仅从已完整验证的恢复图读取原双签身份，不能从服务端 subjects 建立 pin。
	if recovered, ok := proof.(*cryptox.VerifiedIssuerRecoveryProof); ok {
		for _, subject := range out.Subjects {
			id, known := recovered.VerifiedIdentity(subject.DeviceID)
			if !known {
				return nil, own, cryptox.ErrInvalidWire
			}
			if prior, exists := identities[id.DeviceID]; exists && (prior.SigningPublicKey != id.SigningPublicKey || prior.ReceivingPublicKey != id.ReceivingPublicKey) {
				return nil, own, cryptox.ErrInvalidWire
			}
			identities[id.DeviceID] = ManagementSubject{DeviceID: id.DeviceID, SigningPublicKey: id.SigningPublicKey, ReceivingPublicKey: id.ReceivingPublicKey}
		}
	}
	seen := map[string]bool{}
	for _, subject := range out.Subjects {
		identity, known := identities[subject.DeviceID]
		if !known || seen[subject.DeviceID] || !enrollmentID.MatchString(subject.DeviceID) || subject.SigningPublicKey != identity.SigningPublicKey || subject.ReceivingPublicKey != identity.ReceivingPublicKey {
			return nil, own, cryptox.ErrInvalidWire
		}
		seen[subject.DeviceID] = true
		highest, e := strconv.ParseUint(subject.HighestGrantGeneration, 10, 64)
		if e != nil || strconv.FormatUint(highest, 10) != subject.HighestGrantGeneration {
			return nil, own, cryptox.ErrInvalidWire
		}
		if subject.CurrentGrant == nil {
			if highest != 0 {
				return nil, own, cryptox.ErrInvalidWire
			}
			continue
		}
		g := subject.CurrentGrant.Grant
		if g.AccountID != out.AccountID || g.AccountGeneration != out.AccountGeneration || g.EnvironmentID != out.EnvironmentID || g.SubjectDeviceID != subject.DeviceID || g.SubjectSigningPublicKey != identity.SigningPublicKey || g.SubjectReceivingPublicKey != identity.ReceivingPublicKey || g.GrantGeneration != subject.HighestGrantGeneration || highest == 0 {
			return nil, own, cryptox.ErrInvalidWire
		}
		if e = proof.VerifyHistoricalGrant(*subject.CurrentGrant); e != nil {
			return nil, own, e
		}
		if subject.DeviceID == c.config.DeviceID {
			own = *subject.CurrentGrant
		}
	}
	if own.Grant.Role != "admin" || own.Grant.KeyVersion != out.KeyVersion || proof.VerifyTarget(own, c.config.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
		return nil, own, ErrWritePermission
	}
	expiry, e := strconv.ParseInt(own.Grant.ExpiresAt, 10, 64)
	if e != nil || (len(historical) == 0 && expiry != 0 && expiry <= c.config.Now().Unix()) {
		return nil, own, ErrWritePermission
	}
	cached, exists := state.Cloud.Environments[out.EnvironmentID]
	if len(historical) == 0 && (!exists || cached.Role != localstate.Admin || cached.KeyVersion != version || own.Grant.GrantGeneration != strconv.FormatUint(cached.GrantGeneration, 10)) {
		return nil, own, ErrFullPullRequired
	}
	return proof, own, nil
}
func (c *Client) ManagementControl(ctx context.Context, environment string) (ManagementControl, error) {
	var out ManagementControl
	if !enrollmentID.MatchString(environment) {
		return out, cryptox.ErrInvalidWire
	}
	if c.config.Engine.State().Paused {
		return out, ErrPaused
	}
	if e := c.requestManagementControl(ctx, environment, &out); e != nil {
		return out, e
	}
	if out.EnvironmentID != environment {
		return ManagementControl{}, cryptox.ErrInvalidWire
	}
	if _, _, e := c.verifyManagementControl(out); e != nil {
		return ManagementControl{}, e
	}
	return out, nil
}

var ErrGrantUpdateConflict = errors.New("original grant update intent or receipt changed")

// GrantUpdateIntent 只含明确用户选择，不接受调用者提供目录公钥/封套/授权代际。
type GrantUpdateIntent struct {
	ID              string `json:"id"`
	EnvironmentID   string `json:"environmentId"`
	SubjectDeviceID string `json:"subjectDeviceId"`
	Role            string `json:"role"`
	ExpiresAt       int64  `json:"expiresAt"`
}
type grantUpdateRecord struct {
	Version      int                     `json:"version"`
	SessionEpoch uint64                  `json:"sessionEpoch"`
	PreparedAt   int64                   `json:"preparedAt"`
	Intent       GrantUpdateIntent       `json:"intent"`
	Control      ManagementControl       `json:"control"`
	Signed       cryptox.SignedGrantWire `json:"signed"`
}

// GrantUpdateTransaction 只供原生 AES 保护的业务层保存；不得交 Dart 或日志。
type GrantUpdateTransaction struct {
	client *Client
	record grantUpdateRecord
}

func (t *GrantUpdateTransaction) ID() string                { return t.record.Intent.ID }
func (t *GrantUpdateTransaction) Intent() GrantUpdateIntent { return t.record.Intent }
func (t *GrantUpdateTransaction) ContentHash() (string, error) {
	return GrantContentHash(t.record.Signed)
}
func (t *GrantUpdateTransaction) ProtectedBytes() ([]byte, error) {
	if e := t.validate(); e != nil {
		return nil, e
	}
	data, e := json.Marshal(t.record)
	if len(data) > 2<<20 {
		return nil, cryptox.ErrInvalidWire
	}
	return data, e
}
func (c *Client) PrepareGrantUpdate(ctx context.Context, in GrantUpdateIntent, key ed25519.PrivateKey) (*GrantUpdateTransaction, error) {
	if c.config.Engine.State().Paused {
		return nil, ErrPaused
	}
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), v.trust.DeviceSigningPublicKey) {
		return nil, ErrWritePermission
	}
	if !enrollmentID.MatchString(in.ID) || len(in.ID) > 64 || !enrollmentID.MatchString(in.EnvironmentID) || !enrollmentID.MatchString(in.SubjectDeviceID) || (in.Role != "ro" && in.Role != "rw" && in.Role != "admin" && in.Role != "none") || in.ExpiresAt < 0 || in.ExpiresAt > 253402300799 || in.Role == "none" && in.ExpiresAt != 0 {
		return nil, cryptox.ErrInvalidWire
	}
	// 已接受的旧 ID 不能重新生成不同的随机 HPKE 封套；必须恢复原密封交易。
	status, e := c.GrantStatus(ctx, in.ID)
	if e != nil {
		return nil, e
	}
	if status.Accepted {
		return nil, ErrGrantUpdateConflict
	}
	control, e := c.ManagementControl(ctx, in.EnvironmentID)
	if e != nil {
		return nil, e
	}
	_, own, e := c.verifyManagementControl(control)
	if e != nil {
		return nil, e
	}
	var target *ManagementSubject
	for i := range control.Subjects {
		if control.Subjects[i].DeviceID == in.SubjectDeviceID {
			target = &control.Subjects[i]
			break
		}
	}
	if target == nil {
		return nil, ErrWritePermission
	}
	highest, e := strconv.ParseUint(target.HighestGrantGeneration, 10, 64)
	if e != nil || highest == ^uint64(0) {
		return nil, cryptox.ErrInvalidWire
	}
	actorExpiry, e := strconv.ParseInt(own.Grant.ExpiresAt, 10, 64)
	if e != nil {
		return nil, e
	}
	expires := in.ExpiresAt
	if in.Role == "none" {
		expires = actorExpiry
	} else if expires != 0 && expires <= c.config.Now().Unix() || actorExpiry != 0 && (expires == 0 || expires > actorExpiry) {
		return nil, ErrWritePermission
	}
	g := cryptox.Grant{AccountID: c.config.AccountID, AccountGeneration: strconv.FormatUint(c.config.AccountGeneration, 10), IssuerDeviceID: c.config.DeviceID, SubjectDeviceID: target.DeviceID, SubjectSigningPublicKey: target.SigningPublicKey, SubjectReceivingPublicKey: target.ReceivingPublicKey, EnvironmentID: in.EnvironmentID, KeyVersion: control.KeyVersion, GrantGeneration: strconv.FormatUint(highest+1, 10), Role: in.Role, ExpiresAt: strconv.FormatInt(expires, 10), IdempotencyKey: in.ID}
	if in.Role != "none" {
		packet, e := cryptox.DecodeBase64(own.Grant.Envelope, 80, 80)
		if e != nil {
			return nil, e
		}
		envKey, e := cryptox.UnwrapEnvironmentKey(v.trust.ReceivingPrivateKey, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: c.config.DeviceID, RecipientGeneration: own.Grant.GrantGeneration, RecipientPublicKey: v.receivingPublicKey}, packet)
		if e != nil {
			return nil, e
		}
		defer clear(envKey)
		envelope, e := cryptox.WrapEnvironmentKey(envKey, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
		if e != nil {
			return nil, e
		}
		g.Envelope = cryptox.EncodeBase64(envelope)
	}
	signed, e := cryptox.SignGrant(g, key)
	if e != nil {
		return nil, e
	}
	transaction := &GrantUpdateTransaction{client: c, record: grantUpdateRecord{Version: 1, SessionEpoch: c.epoch, PreparedAt: c.config.Now().Unix(), Intent: in, Control: control, Signed: cryptox.GrantToWire(signed)}}
	if e = transaction.validate(); e != nil {
		return nil, e
	}
	return transaction, nil
}
func (c *Client) RestoreGrantUpdate(data []byte) (*GrantUpdateTransaction, error) {
	if len(data) == 0 || len(data) > 2<<20 || cryptox.ValidateStrictJSON(data, 2<<20) != nil {
		return nil, cryptox.ErrInvalidWire
	}
	var saved grantUpdateRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&saved) != nil || decoder.Decode(&extra) != io.EOF {
		return nil, cryptox.ErrInvalidWire
	}
	transaction := &GrantUpdateTransaction{client: c, record: saved}
	if e := transaction.validate(); e != nil {
		return nil, e
	}
	return transaction, nil
}
func (t *GrantUpdateTransaction) validate() error {
	c, r := t.client, t.record
	g, in := r.Signed.Grant, r.Intent
	if r.Version != 1 || r.PreparedAt <= 0 || in.ExpiresAt < 0 || in.ExpiresAt > 253402300799 || c.config.Now().Unix() < r.PreparedAt-5 || r.SessionEpoch != c.epoch || c.config.Engine.State().SessionEpoch != c.epoch || c.config.Engine.State().AccountClosed || !enrollmentID.MatchString(in.ID) || len(in.ID) > 64 || g.EnvironmentID != in.EnvironmentID || g.SubjectDeviceID != in.SubjectDeviceID || g.IdempotencyKey != in.ID || g.Role != in.Role {
		return cryptox.ErrInvalidWire
	}
	if e := c.grantIdentity(r.Signed); e != nil {
		return e
	}
	_, own, e := c.verifyManagementControl(r.Control, true)
	if e != nil {
		return e
	}
	if r.Control.EnvironmentID != g.EnvironmentID || r.Control.KeyVersion != g.KeyVersion {
		return cryptox.ErrInvalidWire
	}
	actorExpiry, e := strconv.ParseInt(own.Grant.ExpiresAt, 10, 64)
	if e != nil || actorExpiry != 0 && r.PreparedAt >= actorExpiry {
		return cryptox.ErrInvalidWire
	}
	expires := in.ExpiresAt
	if in.Role == "none" {
		if expires != 0 {
			return cryptox.ErrInvalidWire
		}
		expires = actorExpiry
	}
	if g.ExpiresAt != strconv.FormatInt(expires, 10) || in.Role != "none" && (expires != 0 && expires <= r.PreparedAt || actorExpiry != 0 && (expires == 0 || expires > actorExpiry)) {
		return cryptox.ErrInvalidWire
	}
	for _, target := range r.Control.Subjects {
		if target.DeviceID == g.SubjectDeviceID {
			highest, e := strconv.ParseUint(target.HighestGrantGeneration, 10, 64)
			if e != nil || highest == ^uint64(0) || g.GrantGeneration != strconv.FormatUint(highest+1, 10) || g.SubjectSigningPublicKey != target.SigningPublicKey || g.SubjectReceivingPublicKey != target.ReceivingPublicKey {
				return cryptox.ErrInvalidWire
			}
			return nil
		}
	}
	return cryptox.ErrInvalidWire
}
func (t *GrantUpdateTransaction) Status(ctx context.Context) (GrantStatus, error) {
	if e := t.validate(); e != nil {
		return GrantStatus{}, e
	}
	status, e := t.client.GrantStatus(ctx, t.ID())
	if e != nil {
		return status, e
	}
	if status.Accepted {
		hash, e := t.ContentHash()
		if e != nil || status.ContentHash != hash || status.Sequence <= t.record.Control.Sequence {
			return GrantStatus{}, ErrGrantUpdateConflict
		}
	}
	return status, nil
}
func (t *GrantUpdateTransaction) Submit(ctx context.Context) (Acceptance, error) {
	return t.submit(ctx, nil)
}

// SubmitWithBarrier 在本次权限/代际检查后、HTTP写请求前调用原生持久化屏障。
func (t *GrantUpdateTransaction) SubmitWithBarrier(ctx context.Context, beforePost func() error) (Acceptance, error) {
	if beforePost == nil {
		return Acceptance{}, cryptox.ErrInvalidWire
	}
	return t.submit(ctx, beforePost)
}
func (t *GrantUpdateTransaction) submit(ctx context.Context, beforePost func() error) (Acceptance, error) {
	if e := t.validate(); e != nil {
		return Acceptance{}, e
	}
	if t.client.config.Engine.State().Paused {
		return Acceptance{}, ErrPaused
	}
	fresh, e := t.client.ManagementControl(ctx, t.record.Intent.EnvironmentID)
	if e != nil {
		return Acceptance{}, e
	}
	_, actor, e := t.client.verifyManagementControl(fresh)
	if e != nil {
		return Acceptance{}, e
	}
	expiry, _ := strconv.ParseInt(t.record.Signed.Grant.ExpiresAt, 10, 64)
	ceiling, _ := strconv.ParseInt(actor.Grant.ExpiresAt, 10, 64)
	if expiry != 0 && expiry <= t.client.config.Now().Unix() || ceiling != 0 && (expiry == 0 || expiry > ceiling) {
		return Acceptance{}, ErrWritePermission
	}
	// 不以新代际重签：竞态只能返回冲突或重查原接受收据。
	found := false
	for _, target := range fresh.Subjects {
		if target.DeviceID == t.record.Intent.SubjectDeviceID {
			next, e := strconv.ParseUint(target.HighestGrantGeneration, 10, 64)
			if e != nil || next == ^uint64(0) || strconv.FormatUint(next+1, 10) != t.record.Signed.Grant.GrantGeneration || fresh.KeyVersion != t.record.Signed.Grant.KeyVersion || target.SigningPublicKey != t.record.Signed.Grant.SubjectSigningPublicKey || target.ReceivingPublicKey != t.record.Signed.Grant.SubjectReceivingPublicKey {
				return Acceptance{}, ErrGrantUpdateConflict
			}
			found = true
		}
	}
	if !found {
		return Acceptance{}, ErrGrantUpdateConflict
	}
	if beforePost != nil {
		if e := beforePost(); e != nil {
			return Acceptance{}, e
		}
	}
	var accepted Acceptance
	if e = t.client.request(ctx, "POST", t.client.endpointFor("/grants"), t.record.Signed, &accepted); e != nil {
		return accepted, e
	}
	if accepted.Sequence <= t.record.Control.Sequence || accepted.Sequence > 9007199254740991 {
		return Acceptance{}, cryptox.ErrInvalidWire
	}
	return accepted, nil
}
func (t *GrantUpdateTransaction) Confirm(ctx context.Context, accepted Acceptance) (SubmitResult, error) {
	out := SubmitResult{Accepted: accepted}
	status, e := t.Status(ctx)
	if e != nil {
		return out, e
	}
	if !status.Accepted || status.Sequence != accepted.Sequence {
		return out, ErrAcceptedNotApplied
	}
	if _, e = t.client.Pull(ctx); e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	if t.client.config.Engine.State().Cloud.Sequence < accepted.Sequence {
		return out, ErrAcceptedNotApplied
	}
	// 精确状态hash已经绑定原签授权；普通pull只负责收敛自己的云缓存，不猜目标当前值。
	out.Applied = true
	return out, nil
}

func strictTransaction(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(out) != nil || decoder.Decode(&extra) != io.EOF {
		return cryptox.ErrInvalidWire
	}
	return nil
}

// ControlCheckpoint 是原生层保存最高已见授权代际的受签目录快照。
func (t *GrantUpdateTransaction) ControlCheckpoint() ManagementControl {
	return cloneManagementControl(t.record.Control)
}
func cloneManagementControl(value ManagementControl) ManagementControl {
	data, _ := json.Marshal(value)
	var out ManagementControl
	_ = json.Unmarshal(data, &out)
	return out
}
