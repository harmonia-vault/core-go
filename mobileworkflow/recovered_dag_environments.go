package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 独立business journal，原签包/随机封套只生成一次；不是恢复checked journal。
type dagEnvironmentJournal struct {
	Version          int                              `json:"version"`
	Profile          string                           `json:"profile"`
	EnrollmentID     string                           `json:"enrollmentId"`
	EnrollmentHash   string                           `json:"enrollmentHash"`
	Records          map[string]*dagEnvironmentRecord `json:"records"`
	ReceiverControls []syncclient.ManagementControl   `json:"receiverControls"`
}
type dagEnvironmentRecord struct {
	InputHash   string                            `json:"inputHash"`
	ContentHash string                            `json:"contentHash"`
	Signed      cryptox.SignedEnvironmentChange   `json:"signed"`
	Origin      *cryptox.EnvironmentChangeV2      `json:"origin,omitempty"`
	Control     syncclient.EnvironmentControlView `json:"control"`
	Sequence    uint64                            `json:"sequence"`
	Applied     bool                              `json:"applied"`
}

func (r *dagEnvironmentJournal) UnmarshalJSON(raw []byte) error {
	if exactDAGObject(raw, "version", "profile", "enrollmentId", "enrollmentHash", "records", "receiverControls") != nil {
		return ErrDAGProtectedState
	}
	type plain dagEnvironmentJournal
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = dagEnvironmentJournal(out)
	return nil
}
func (r *dagEnvironmentRecord) UnmarshalJSON(raw []byte) error {
	var obj map[string]json.RawMessage
	if decode(raw, &obj) != nil {
		return ErrDAGProtectedState
	}
	fields := []string{"inputHash", "contentHash", "signed", "control", "sequence", "applied"}
	if _, ok := obj["origin"]; ok {
		fields = append(fields, "origin")
	}
	if exactDAGObject(raw, fields...) != nil {
		return ErrDAGProtectedState
	}
	type plain dagEnvironmentRecord
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = dagEnvironmentRecord(out)
	return nil
}

type DAGEnvironmentInfo struct {
	RequestID     string `json:"requestId"`
	Operation     string `json:"operation"`
	EnvironmentID string `json:"environmentId"`
	Sequence      uint64 `json:"sequence"`
	Applied       bool   `json:"applied"`
}
type DAGEnvironmentResult struct {
	Environment DAGEnvironmentInfo
	View        *DAGRecoveredView
}

func dagEnvironmentInfo(r *dagEnvironmentRecord) DAGEnvironmentInfo {
	return DAGEnvironmentInfo{RequestID: r.Signed.Change.IdempotencyKey, Operation: r.Signed.Change.Operation, EnvironmentID: r.Signed.Change.EnvironmentID, Sequence: r.Sequence, Applied: r.Applied}
}
func dagEnvironmentHash(s cryptox.SignedEnvironmentChange, origin *cryptox.EnvironmentChangeV2) (string, error) {
	if origin != nil {
		return cryptox.EnvironmentSubmissionHash(*origin)
	}
	raw, e := s.Change.SigningBytes()
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(cryptox.EncodeBase64(raw) + "." + s.Signature))
	return hex.EncodeToString(sum[:]), nil
}
func validDAGDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func (w *Workflow) dagEnvironmentHistoryClient() (*syncclient.Client, func(), error) {
	v, e := w.recoveredDAGVerifierLocked()
	if e != nil {
		return nil, nil, e
	}
	g, e := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if e != nil {
		v.Close()
		return nil, nil, e
	}
	c, e := syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, ProtocolMajor: 2, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: g, DeviceID: w.state.DeviceID, Verifier: v, Engine: w.engine, Now: w.now})
	if e != nil {
		v.Close()
		return nil, nil, e
	}
	return c, v.Close, nil
}
func (w *Workflow) validateDAGEnvironmentsLocked() error {
	j := w.state.DAGEnvironments
	if j == nil {
		return nil
	}
	if w.state.RecoveredDAGDevice == nil || j.Version != 1 || j.Profile != cryptox.RecoveryDAGCapability || j.Records == nil || j.ReceiverControls == nil || len(j.Records)+len(j.ReceiverControls) == 0 || len(j.Records) > 32 || len(j.ReceiverControls) > 32 {
		return ErrDAGProtectedState
	}
	raw, e := json.Marshal(j)
	if e != nil || len(raw) > 8<<20 {
		return ErrDAGProtectedState
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil || j.EnrollmentID != p.OperationID || j.EnrollmentHash != p.ContentHash {
		return ErrDAGProtectedState
	}
	c, close, e := w.dagEnvironmentHistoryClient()
	if e != nil {
		return e
	}
	defer close()
	if _, e = w.verifyDAGReceiverHistory(c); e != nil {
		return e
	}
	for id, r := range j.Records {
		if r == nil || r.Signed.Change.IdempotencyKey != id || !identifier.MatchString(id) || len(id) > 64 || !validDAGDigest(r.InputHash) || !validDAGDigest(r.ContentHash) {
			return ErrDAGProtectedState
		}
		ch := r.Signed.Change
		if ch.AccountID != w.state.AccountID || ch.AccountGeneration != w.state.AccountGeneration || ch.DeviceID != w.state.DeviceID || cryptox.VerifyEnvironmentChange(r.Signed, w.signing.Public().(ed25519.PublicKey)) != nil {
			return ErrDAGProtectedState
		}
		if ch.Operation != "create" && ch.Operation != "rename" && ch.Operation != "rotate" && ch.Operation != "delete" {
			return ErrDAGProtectedState
		}
		expected, e := strconv.ParseUint(ch.ExpectedSequence, 10, 64)
		if e != nil || expected != r.Control.Sequence || expected >= 9007199254740991 || uint64(len(ch.Mutations)) > 9007199254740990-expected {
			return ErrDAGProtectedState
		}
		tail := expected + 1 + uint64(len(ch.Mutations))
		if r.Sequence != 0 && r.Sequence != tail || r.Applied && r.Sequence == 0 {
			return ErrDAGProtectedState
		}
		graph, e := c.VerifyEnvironmentControl(r.Control, ch.AuthorityEnvironmentID, true)
		if e != nil {
			return e
		}
		dag, ok := graph.(*cryptox.VerifiedRecoveryDAG)
		if !ok {
			return ErrDAGProtectedState
		}
		head, e := dag.RecoveryCheckpoint()
		if e != nil || head.RecoveryGeneration != ch.RecoveryGeneration {
			return ErrDAGProtectedState
		}
		var actor cryptox.SignedGrantWire
		for _, g := range r.Control.Grants {
			if g.Grant.SubjectDeviceID == w.state.DeviceID {
				actor = g
			}
		}
		if actor.Grant.KeyVersion != ch.AuthorityKeyVersion || actor.Grant.GrantGeneration != ch.AuthorityGrantGeneration {
			return ErrDAGProtectedState
		}
		if ch.Operation == "create" || ch.Operation == "rotate" {
			if r.Origin == nil || !sameJSONValue(r.Signed, cryptox.SignedEnvironmentChange{Change: r.Origin.Change, Signature: r.Origin.Signature}) {
				return ErrDAGProtectedState
			}
			before := []cryptox.SignedGrantWire{}
			if ch.Operation == "rotate" {
				before = r.Control.Grants
				matched := false
				for _, management := range j.ReceiverControls {
					if management.EnvironmentID == ch.EnvironmentID && matchDAGReceivers(r.Control, management, w.now().Unix(), true) == nil {
						matched = true
						break
					}
				}
				if !matched {
					return ErrDAGProtectedState
				}
			}
			if e = cryptox.VerifyEnvironmentOriginChange(r.Signed, r.Origin.Origin, actor, before, w.signing.Public().(ed25519.PublicKey)); e != nil {
				return e
			}
		} else if r.Origin != nil || ch.EnvironmentID != ch.AuthorityEnvironmentID || ch.KeyVersion != actor.Grant.KeyVersion || ch.PreviousKeyVersion != ch.KeyVersion {
			return ErrDAGProtectedState
		}
		hash, e := dagEnvironmentHash(r.Signed, r.Origin)
		if e != nil || hash != r.ContentHash {
			return ErrDAGProtectedState
		}
		if r.Applied {
			if e = syncclient.VerifyEnvironmentChangeCheckpoint(w.engine.State().Cloud, r.Signed, r.Sequence); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w *Workflow) PendingDAGEnvironments() ([]DAGEnvironmentInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		return nil, ErrDAGQueryBusy
	}
	if w.state.RecoveredDAGDevice == nil {
		return nil, ErrNotTrusted
	}
	if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
		return nil, e
	}
	rows := []DAGEnvironmentInfo{}
	if j := w.state.DAGEnvironments; j != nil {
		ids := []string{}
		for id := range j.Records {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			rows = append(rows, dagEnvironmentInfo(j.Records[id]))
		}
	}
	return rows, nil
}
func (w *Workflow) CreateDAGEnvironment(ctx context.Context, authorityEnv, name, id string) (DAGEnvironmentResult, error) {
	return w.runDAGEnvironment(ctx, "create", authorityEnv, "", name, id)
}
func (w *Workflow) RenameDAGEnvironment(ctx context.Context, env, name, id string) (DAGEnvironmentResult, error) {
	return w.runDAGEnvironment(ctx, "rename", env, env, name, id)
}
func (w *Workflow) RotateDAGEnvironment(ctx context.Context, env, id string) (DAGEnvironmentResult, error) {
	return w.runDAGEnvironment(ctx, "rotate", env, env, "", id)
}
func (w *Workflow) DeleteDAGEnvironment(ctx context.Context, env, id string) (DAGEnvironmentResult, error) {
	return w.runDAGEnvironment(ctx, "delete", env, env, "", id)
}
func (w *Workflow) RetryDAGEnvironment(ctx context.Context, id string) (DAGEnvironmentResult, error) {
	return w.runDAGEnvironment(ctx, "retry", "", "", "", id)
}

func (w *Workflow) prepareDAGEnvironment(ctx context.Context, op, authorityEnv, env, name, id, inputHash string, commit *dagActiveWriteLog) (*dagEnvironmentRecord, error) {
	authority, e := w.grant(authorityEnv)
	if e != nil || authority.Role != "admin" {
		return nil, syncclient.ErrWritePermission
	}
	control, e := w.client.EnvironmentControl(ctx, authorityEnv)
	if e != nil {
		return nil, e
	}
	if control.Sequence != w.engine.State().Cloud.Sequence {
		return nil, syncclient.ErrWriteConflict
	}
	graph, e := w.client.VerifyEnvironmentControl(control, authorityEnv)
	if e != nil {
		return nil, e
	}
	dag, ok := graph.(*cryptox.VerifiedRecoveryDAG)
	if !ok {
		return nil, ErrDAGProtectedState
	}
	head, e := dag.RecoveryCheckpoint()
	if e != nil {
		return nil, e
	}
	if op == "rotate" {
		if e = w.verifyAndCommitDAGReceivers(ctx, control, env, commit); e != nil {
			return nil, e
		}
	}
	if op == "create" {
		env, e = randomID()
		if e != nil {
			return nil, e
		}
	}
	ch := w.baseChange(env, op, id, authority)
	ch.RecoveryGeneration = head.RecoveryGeneration
	ch.Grants = []cryptox.SignedGrantWire{}
	ch.Mutations = []cryptox.SignedMutationWire{}
	var key []byte
	if op == "create" || op == "rotate" {
		key, e = cryptox.GenerateEnvironmentKey()
		if op == "create" {
			ch.PreviousKeyVersion = "0"
			ch.KeyVersion = "1"
		} else {
			v, e := strconv.ParseUint(authority.KeyVersion, 10, 64)
			if e != nil || v == ^uint64(0) {
				return nil, cryptox.ErrInvalidWire
			}
			ch.KeyVersion = strconv.FormatUint(v+1, 10)
			name = env
			if label, ok := w.state.Labels[env]; ok {
				name = label.Name
			}
		}
	} else if op == "rename" {
		key, e = w.environmentKey(env)
	}
	if e != nil {
		return nil, e
	}
	defer clear(key)
	if op != "delete" {
		label, e := cryptox.EncryptEnvironmentLabel(key, cryptox.EnvironmentLabelContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: ch.KeyVersion}, []byte(name))
		if e != nil {
			return nil, e
		}
		ch.LabelPayload = cryptox.EncodeBase64(label)
	}
	prefixHash := sha256.Sum256([]byte(id))
	prefix := "env-" + hex.EncodeToString(prefixHash[:16])
	if op == "create" {
		grant, e := w.makeGrant(env, "1", "1", prefix+"-g-0", key, authority.ExpiresAt)
		if e != nil {
			return nil, e
		}
		ch.Grants = append(ch.Grants, grant)
	}
	if op == "create" || op == "rotate" {
		wrapped, e := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: ch.KeyVersion, RecipientType: "recovery", RecipientID: w.state.AccountID, RecipientGeneration: head.RecoveryGeneration, RecipientPublicKey: head.ReceivingPublicKey})
		if e != nil {
			return nil, e
		}
		ch.RecoveryEnvelope = cryptox.EncodeBase64(wrapped)
	}
	if op == "rotate" {
		ownGeneration := ""
		for i, prior := range control.Grants {
			g := prior.Grant
			n, e := strconv.ParseUint(g.GrantGeneration, 10, 64)
			if e != nil || n == ^uint64(0) {
				return nil, cryptox.ErrInvalidWire
			}
			g.IssuerDeviceID = w.state.DeviceID
			g.KeyVersion = ch.KeyVersion
			g.GrantGeneration = strconv.FormatUint(n+1, 10)
			g.IdempotencyKey = prefix + "-g-" + strconv.Itoa(i)
			wrapped, e := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: ch.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
			if e != nil {
				return nil, e
			}
			g.Envelope = cryptox.EncodeBase64(wrapped)
			signed, e := cryptox.SignGrant(g, w.signing)
			if e != nil {
				return nil, e
			}
			ch.Grants = append(ch.Grants, cryptox.GrantToWire(signed))
			if g.SubjectDeviceID == w.state.DeviceID {
				ownGeneration = g.GrantGeneration
			}
		}
		if ownGeneration == "" {
			return nil, syncclient.ErrWritePermission
		}
		values := w.engine.State().Cloud.Environments[env].Values
		names := []string{}
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for i, name := range names {
			payload, e := cryptox.EncryptValue(key, cryptox.ValueContext{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, EnvironmentID: env, KeyVersion: ch.KeyVersion, Name: name}, []byte(values[name]))
			if e != nil {
				return nil, e
			}
			m := cryptox.Mutation{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, DeviceID: w.state.DeviceID, EnvironmentID: env, KeyVersion: ch.KeyVersion, GrantGeneration: ownGeneration, Operation: "put", IdempotencyKey: prefix + "-v-" + strconv.Itoa(i), Name: name, Payload: cryptox.EncodeBase64(payload)}
			signed, e := cryptox.SignMutation(m, w.signing)
			if e != nil {
				return nil, e
			}
			ch.Mutations = append(ch.Mutations, cryptox.MutationToWire(signed))
		}
	}
	signed, e := cryptox.SignEnvironmentChange(ch, w.signing)
	if e != nil {
		return nil, e
	}
	record := &dagEnvironmentRecord{InputHash: inputHash, Signed: signed, Control: control}
	if op == "create" || op == "rotate" {
		var actor cryptox.SignedGrantWire
		for _, g := range control.Grants {
			if g.Grant.SubjectDeviceID == w.state.DeviceID {
				actor = g
			}
		}
		before := []cryptox.SignedGrantWire{}
		if op == "rotate" {
			before = control.Grants
		}
		packet, e := cryptox.NewEnvironmentChangeV2(signed, actor, before, w.signing)
		if e != nil {
			return nil, e
		}
		record.Origin = &packet
	}
	record.ContentHash, e = dagEnvironmentHash(signed, record.Origin)
	return record, e
}

func (w *Workflow) submitDAGEnvironment(ctx context.Context, r *dagEnvironmentRecord, commit *dagActiveWriteLog) (err error) {
	// status只确认原包；unknown才能在当前权限/精确原basis仍成立时重发原包。
	var result syncclient.SubmitResult
	complete := false
	var sequence uint64
	if r.Origin != nil {
		status, e := w.client.EnvironmentStatusV4(ctx, r.Signed.Change.IdempotencyKey)
		if e != nil {
			return errors.Join(syncclient.ErrWritePending, e)
		}
		complete, sequence = status.State == "complete", status.Sequence
		if complete && status.ContentHash != r.ContentHash {
			return syncclient.ErrWriteConflict
		}
	} else {
		status, e := w.client.EnvironmentStatus(ctx, r.Signed.Change.IdempotencyKey)
		if e != nil {
			return errors.Join(syncclient.ErrWritePending, e)
		}
		complete, sequence = status.State == "complete", status.Sequence
	}
	if complete {
		if r.Sequence != 0 && r.Sequence != sequence {
			return syncclient.ErrWriteConflict
		}
		if r.Origin != nil {
			result, err = w.client.ConfirmEnvironmentChangeV4(ctx, *r.Origin, syncclient.Acceptance{Sequence: sequence, Replayed: true})
		} else {
			result, err = w.client.ConfirmEnvironmentChange(ctx, r.Signed, syncclient.Acceptance{Sequence: sequence, Replayed: true})
		}
	} else {
		if r.Sequence != 0 {
			return syncclient.ErrWriteConflict
		}
		ch := r.Signed.Change
		authority, e := w.grant(ch.AuthorityEnvironmentID)
		if e != nil || authority.Role != "admin" || authority.KeyVersion != ch.AuthorityKeyVersion || authority.GrantGeneration != ch.AuthorityGrantGeneration {
			return syncclient.ErrWritePermission
		}
		control, e := w.client.EnvironmentControl(ctx, ch.AuthorityEnvironmentID)
		if e != nil {
			return e
		}
		if control.Sequence != r.Control.Sequence {
			return syncclient.ErrWriteConflict
		}
		graph, e := w.client.VerifyEnvironmentControl(control, ch.AuthorityEnvironmentID)
		if e != nil {
			return e
		}
		dag, ok := graph.(*cryptox.VerifiedRecoveryDAG)
		if !ok {
			return ErrDAGProtectedState
		}
		head, e := dag.RecoveryCheckpoint()
		if e != nil {
			return e
		}
		if head.RecoveryGeneration != ch.RecoveryGeneration {
			return syncclient.ErrWriteConflict
		}
		if ch.Operation == "rotate" {
			if e = w.verifyAndCommitDAGReceivers(ctx, control, ch.EnvironmentID, commit, r.Control); e != nil {
				return e
			}
		}
		if e = commit.commitCandidate(); e != nil {
			return e
		} // native beforePOST barrier，同完整原包。
		if r.Origin != nil {
			result, err = w.client.SubmitEnvironmentChangeV4(ctx, *r.Origin)
		} else {
			result, err = w.client.SubmitEnvironmentChange(ctx, r.Signed)
		}
	}
	if result.Accepted.Sequence > 0 {
		if r.Sequence != 0 && r.Sequence != result.Accepted.Sequence {
			return syncclient.ErrWriteConflict
		}
		r.Sequence = result.Accepted.Sequence
	}
	r.Applied = false
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return errors.Join(err, commit.commitCandidate())
		}
		var fault *syncclient.RequestError
		if errors.As(err, &fault) && fault.Status == 403 {
			_, refreshErr := w.client.RefreshAuthorizations(ctx)
			return errors.Join(syncclient.ErrWritePermission, err, refreshErr, commit.commitCandidate())
		}
		saveErr := commit.commitCandidate()
		if errors.As(err, &fault) && fault.Status < 500 {
			return errors.Join(err, saveErr)
		}
		return errors.Join(syncclient.ErrWritePending, err, saveErr)
	}
	r.Applied = result.Applied
	if e := commit.commitCandidate(); e != nil {
		r.Applied = false
		return errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	if !r.Applied {
		return syncclient.ErrAcceptedNotApplied
	}
	return nil
}

func (w *Workflow) runDAGEnvironment(ctx context.Context, op, authorityEnv, env, name, id string) (out DAGEnvironmentResult, err error) {
	defer func() {
		if err != nil {
			out.Environment.Applied = false
			out.View = nil
		}
	}()
	if !identifier.MatchString(id) || len(id) > 64 {
		return out, syncclient.ErrWriteInput
	}
	if op != "retry" {
		if !identifier.MatchString(authorityEnv) || len(authorityEnv) > 64 {
			return out, syncclient.ErrWriteInput
		}
		if op == "create" || op == "rename" {
			name, err = environmentName(name)
			if err != nil {
				return out, err
			}
		} else if name != "" {
			return out, syncclient.ErrWriteInput
		}
	}
	w.mu.Lock()
	if w.state.RecoveredDAGDevice == nil {
		w.mu.Unlock()
		return out, ErrNotTrusted
	}
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		w.mu.Unlock()
		return out, ErrDAGQueryBusy
	}
	if err = w.validateRecoveredDAGDeviceLocked(); err != nil {
		w.mu.Unlock()
		return out, err
	}
	if w.engine.State().Paused {
		w.mu.Unlock()
		return out, syncclient.ErrPaused
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil {
		w.mu.Unlock()
		return out, e
	}
	state, hash, epoch := clone(w.state), w.protectedSHA256, w.engine.State().SessionEpoch
	signing, receiving := bytes.Clone(w.signing), bytes.Clone(w.receiving)
	networkCtx, cancel := context.WithCancel(ctx)
	w.dagDeviceCancel = cancel
	candidate := &Workflow{state: state, signing: signing, receiving: receiving, http: w.http, now: w.now}
	w.mu.Unlock()
	commit := &dagActiveWriteLog{owner: w, candidate: candidate, ctx: networkCtx, hash: hash, epoch: epoch}
	defer func() {
		err = errors.Join(err, commit.terminalCause)
		cancel()
		clear(signing)
		clear(receiving)
		if candidate.verifier != nil {
			candidate.verifier.Close()
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.dagDeviceCancel = nil
		if (errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, ErrDAGAuthorizationNotPersisted)) && !w.closed && w.engine != nil && w.protectedSHA256 == commit.hash && w.engine.State().SessionEpoch == epoch {
			err = errors.Join(err, w.engine.Logout(), w.invalidateTrust())
		}
	}()
	candidate.store = &memoryStore{state: clone(state.Cloud)}
	candidate.engine, err = localstate.New(candidate.store)
	if err != nil {
		return out, err
	}
	candidate.verifier, err = candidate.recoveredDAGVerifierLocked()
	if err != nil {
		return out, err
	}
	boot, e := syncclient.NewForBoot(syncclient.Config{Endpoint: state.Endpoint, ProtocolMajor: 2, HTTPClient: candidate.http, AccountID: state.AccountID, AccountGeneration: p.AccountGeneration, DeviceID: state.DeviceID, Verifier: candidate.verifier, Engine: candidate.engine, Now: candidate.now})
	if e != nil {
		return out, e
	}
	candidate.client, err = boot.BootDevice(networkCtx, signing)
	if err != nil {
		return out, err
	}
	candidate.client, err = candidate.client.WithVerifiedPullCommit(networkCtx, commit.commitVerifiedPull)
	if err != nil {
		return out, err
	}
	if err = candidate.pullDAGBusiness(networkCtx); err != nil {
		return out, err
	}
	j := candidate.state.DAGEnvironments
	if j == nil {
		j = &dagEnvironmentJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Records: map[string]*dagEnvironmentRecord{}, ReceiverControls: []syncclient.ManagementControl{}}
	}
	candidate.state.DAGEnvironments = j
	raw, _ := json.Marshal([]string{op, authorityEnv, env, name, id})
	digest := sha256.Sum256(raw)
	inputHash := hex.EncodeToString(digest[:])
	record := j.Records[id]
	if record == nil {
		if op == "retry" {
			return out, syncclient.ErrWriteInput
		}
		if len(j.Records) >= 32 {
			return out, syncclient.ErrWriteJournal
		}
		record, err = candidate.prepareDAGEnvironment(networkCtx, op, authorityEnv, env, name, id, inputHash, commit)
		if err != nil {
			return out, err
		}
		j.Records[id] = record
		candidate.state.DAGEnvironments = j
		if err = commit.commitCandidate(); err != nil {
			return out, err
		}
	} else if op != "retry" && record.InputHash != inputHash {
		return out, syncclient.ErrWriteConflict
	}
	err = candidate.submitDAGEnvironment(networkCtx, record, commit)
	out.Environment = dagEnvironmentInfo(record)
	if err != nil {
		out.Environment.Applied = false
		return out, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.engine == nil || w.dagPersistenceFailed || w.protectedSHA256 != commit.hash || w.engine.State().SessionEpoch != epoch || networkCtx.Err() != nil {
		return out, ErrDAGProtectedState
	}
	if err = w.validateRecoveredDAGDeviceLocked(); err != nil {
		return out, err
	}
	view, e := w.dagRecoveredViewLocked()
	if e != nil {
		return out, e
	}
	out.View = &view
	return out, nil
}
