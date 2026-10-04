package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 完整原登记记录是来源，不能用可信布尔或server目录代替。
type recoveredDAGDeviceRecord struct {
	Version  int              `json:"version"`
	Profile  string           `json:"profile"`
	Original recoveryDAGState `json:"original"`
}

func exactDAGObject(raw []byte, names ...string) error {
	var obj map[string]json.RawMessage
	if decode(raw, &obj) != nil || len(obj) != len(names) {
		return ErrDAGProtectedState
	}
	for _, name := range names {
		value, ok := obj[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrDAGProtectedState
		}
	}
	return nil
}
func (r *recoveredDAGDeviceRecord) UnmarshalJSON(raw []byte) error {
	if exactDAGObject(raw, "version", "profile", "original") != nil {
		return ErrDAGProtectedState
	}
	var obj map[string]json.RawMessage
	if decode(raw, &obj) != nil || exactDAGObject(obj["original"], "version", "profile", "endpoint", "accountId", "accountGeneration", "deviceId", "signingPublicKey", "receivingPublicKey", "ownerEpoch", "journal") != nil {
		return ErrDAGProtectedState
	}
	type plain recoveredDAGDeviceRecord
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = recoveredDAGDeviceRecord(out)
	return nil
}

// DAGRecoveredView只在正式Boot/Pull及最后native whole-state CAS成功后给出。
// 不被当前native ABI导出，不打开旧管理/写/配对业务。
type DAGRecoveredView struct {
	Version          int    `json:"version"`
	Profile          string `json:"profile"`
	OperationID      string `json:"operationId"`
	ContentHash      string `json:"contentHash"`
	AcceptedSequence uint64 `json:"acceptedSequence"`
	TrustedDevice    bool   `json:"trustedDevice"`
	View             View   `json:"view"`
}

func (w *Workflow) failDAGPersistenceLocked() {
	w.dagPersistenceFailed = true
	if w.dagDeviceCancel != nil {
		w.dagDeviceCancel()
	}
	if w.dagOwnerCancel != nil {
		w.dagOwnerCancel()
	}
	if w.dagQueryCancel != nil {
		w.dagQueryCancel()
	}
}
func (w *Workflow) recoveredDAGOriginalLocked(r recoveryDAGState) (syncclient.ProtectedDAGOperation, error) {
	gen, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || gen == 0 || strconv.FormatUint(gen, 10) != w.state.AccountGeneration || r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || r.Endpoint != w.state.Endpoint || r.AccountID != w.state.AccountID || r.AccountGeneration != gen || r.DeviceID != w.state.DeviceID || r.SigningPublicKey != w.state.SigningPublicKey || r.ReceivingPublicKey != w.state.ReceivingPublicKey || r.OwnerEpoch > w.engine.State().SessionEpoch {
		return syncclient.ProtectedDAGOperation{}, ErrDAGProtectedState
	}
	p, err := syncclient.DecodeDAGJournal(syncclient.DAGJournalBinding{Endpoint: r.Endpoint, AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, OwnerEpoch: r.OwnerEpoch}, r.Journal)
	if err != nil {
		return p, err
	}
	if err = w.validateDAGDeviceLocked(p); err != nil {
		return p, err
	}
	_, err = syncclient.RecoveredDAGResultFromConfirmedOperation(p)
	return p, err
}
func recoveredDAGRoot(result syncclient.DAGRecoveredResult) cryptox.TrustRoot {
	p := result.Evidence.Initialization.Proposal
	return cryptox.TrustRoot{RootDeviceID: p.Device.ID, RootSigningPublicKey: p.Device.SigningPublicKey, RootReceivingPublicKey: p.Device.ReceivingPublicKey, RecoveryGeneration: p.RecoveryGeneration, RecoverySigningPublicKey: p.RecoverySigningPublicKey, RecoveryReceivingPublicKey: p.RecoveryReceivingPublicKey, Signature: p.TrustRootSignature}
}
func (w *Workflow) recoveredDAGVerifierLocked() (*syncclient.PinnedVerifier, error) {
	r := w.state.RecoveredDAGDevice
	if r == nil {
		return nil, ErrNotTrusted
	}
	p, err := w.recoveredDAGOriginalLocked(r.Original)
	if err != nil {
		return nil, err
	}
	result, err := syncclient.RecoveredDAGResultFromConfirmedOperation(p)
	if err != nil {
		return nil, err
	}
	return syncclient.NewRecoveredDAGPinnedVerifier(syncclient.RecoveredDAGPinnedTrust{Trust: syncclient.PinnedTrust{AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: w.signing.Public().(ed25519.PublicKey), ReceivingPrivateKey: w.receiving, Now: w.now}, Pin: result.Pin, Accepted: result.Accepted, Evidence: result.Evidence})
}
func (w *Workflow) validateRecoveredDAGDeviceLocked() error {
	r := w.state.RecoveredDAGDevice
	if r == nil {
		if w.state.DAGWrites != nil || w.state.DAGEnvironments != nil {
			return ErrDAGProtectedState
		}
		return nil
	}
	if r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || !w.state.DAGCASRequired || w.state.RecoveryDAG != nil || w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil || w.state.Pending != nil || w.state.Recovery != nil || w.state.RecoveryAuthority != nil || w.state.RecoveredDevice != nil || w.state.EnrollmentV3 != nil || w.state.PendingApproval != nil || w.state.PendingApprovalV3 != nil || w.state.PendingApprovalV4 != nil || w.state.Management != nil || len(w.state.WriteJournal) > 0 || len(w.state.EnvironmentWrites) > 0 || len(w.state.InitialAuthorities) > 0 || len(w.state.SelfRevocation) > 0 || w.state.Root == nil || w.engine.State().AccountClosed {
		return ErrDAGProtectedState
	}
	if err := w.checkRecoveredDAGNativeLocked(); err != nil {
		return err
	}
	p, err := w.recoveredDAGOriginalLocked(r.Original)
	if err != nil {
		return err
	}
	result, err := syncclient.RecoveredDAGResultFromConfirmedOperation(p)
	if err != nil {
		return err
	}
	if *w.state.Root != recoveredDAGRoot(result) {
		return ErrDAGProtectedState
	}
	cloud := w.engine.State().Cloud
	if r := w.state.RecoveryDAGResolution; r != nil && cloud.Sequence < r.Baseline.MinimumSequence {
		return ErrDAGProtectedState
	}
	if cloud.AccountID != p.AccountID || cloud.AccountGeneration != p.AccountGeneration || cloud.Sequence < p.AcceptedSequence || cloud.AuthorizationSequence < cloud.Sequence || len(cloud.IssuerEvidence) == 0 {
		return ErrDAGProtectedState
	}
	v, err := w.recoveredDAGVerifierLocked()
	if err != nil {
		return err
	}
	defer v.Close()
	if err = v.ValidateStoredIssuerEvidence(cloud); err != nil {
		return err
	}
	evidence, err := cryptox.DecodeIssuerRecoveryDAG(cloud.IssuerEvidence)
	if err != nil {
		return err
	}
	proof, err := cryptox.VerifyIssuerRecoveryDAG(result.Pin, evidence)
	if err != nil {
		return err
	}
	if err = syncclient.ValidateDAGClosedHistory(resolutionClosedCheckpoints(w.state.RecoveryDAGResolution), evidence.Records); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, g := range w.state.Grants {
		b, e := g.Grant.SigningBytes()
		gg, e2 := strconv.ParseUint(g.Grant.GrantGeneration, 10, 64)
		if e != nil || e2 != nil || seen[g.Grant.EnvironmentID] || g.Grant.AccountID != p.AccountID || g.Grant.AccountGeneration != p.Pin.AccountGeneration || g.Grant.SubjectDeviceID != w.state.DeviceID || g.Grant.SubjectSigningPublicKey != w.state.SigningPublicKey || g.Grant.SubjectReceivingPublicKey != w.state.ReceivingPublicKey || cloud.GrantCheckpoints[g.Grant.EnvironmentID] != gg || cloud.GrantFingerprints[g.Grant.EnvironmentID] != protectedStateHash(b) || proof.VerifyHistoricalGrant(g) != nil {
			return ErrDAGProtectedState
		}
		seen[g.Grant.EnvironmentID] = true
	}
	for id := range cloud.Environments {
		if !seen[id] {
			return ErrDAGProtectedState
		}
	}
	for id, label := range w.state.Labels {
		env, ok := cloud.Environments[id]
		if !ok || label.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || label.Sequence > cloud.Sequence {
			return ErrDAGProtectedState
		}
	}
	if err := w.validateDAGWritesLocked(); err != nil {
		return err
	}
	return w.validateDAGEnvironmentsLocked()
}
func (w *Workflow) checkRecoveredDAGNativeLocked() error {
	if w.closed || w.engine == nil {
		return ErrClosed
	}
	if w.dagPersistenceFailed {
		return ErrDAGPersistence
	}
	if w.saveNativeCAS == nil || w.checkNativeState == nil {
		return ErrDAGAtomicStoreRequired
	}
	if err := w.checkNativeState(w.protectedSHA256); err != nil {
		w.failDAGPersistenceLocked()
		return errors.Join(ErrDAGPersistence, err)
	}
	return nil
}
func (w *Workflow) dagRecoveredViewLocked() (DAGRecoveredView, error) {
	p, err := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if err != nil {
		return DAGRecoveredView{}, err
	}
	return DAGRecoveredView{Version: 1, Profile: cryptox.RecoveryDAGCapability, OperationID: p.OperationID, ContentHash: p.ContentHash, AcceptedSequence: p.AcceptedSequence, TrustedDevice: true, View: w.view()}, nil
}

// RestoreDAGRecoveredDevice只读本机保护来源；到期清理也必须同whole-state CAS保存。
func (w *Workflow) RestoreDAGRecoveredDevice() (DAGRecoveredView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.RecoveredDAGDevice == nil {
		return DAGRecoveredView{}, ErrNotTrusted
	}
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		return DAGRecoveredView{}, ErrDAGQueryBusy
	}
	if err := w.validateRecoveredDAGDeviceLocked(); err != nil {
		return DAGRecoveredView{}, err
	}
	if _, err := w.engine.Effective(w.now()); err != nil {
		return DAGRecoveredView{}, err
	}
	cleanDAGLabels(&w.state, w.engine.State())
	if err := w.persist(); err != nil {
		return DAGRecoveredView{}, err
	}
	return w.dagRecoveredViewLocked()
}
func cleanDAGLabels(s *protectedState, cloud localstate.State) {
	for id, label := range s.Labels {
		env, ok := cloud.Cloud.Environments[id]
		if !ok || label.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) {
			delete(s.Labels, id)
		}
	}
}

// retire仅处理当前精确idle owner。不得持Workflow锁等待session.Close或busy lease。
func retireAppliedDAGOwner(r *DAGRecoveryRegistry, scope DAGOwnerScope, identity dagOwnerIdentity) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.scope != scope || !validDAGOwnerScope(scope) {
		r.mu.Unlock()
		return ErrDAGOwnerBinding
	}
	e := r.current
	if e == nil {
		r.mu.Unlock()
		return nil
	}
	if e.busy {
		r.mu.Unlock()
		return ErrDAGQueryBusy
	}
	if e.identity != identity || e.phase != "device-original-applied" {
		r.mu.Unlock()
		return ErrDAGOwnerBinding
	}
	e.retired.Store(true)
	if e.timer != nil {
		e.timer.Stop()
	}
	if e.cancel != nil {
		e.cancel()
	}
	r.mu.Unlock()
	e.closeOwner()
	return nil
}
func (w *Workflow) ApplyDAGRecoveredDevice(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope) (DAGRecoveredView, error) {
	return w.updateDAGRecoveredDevice(ctx, r, scope, false)
}
func (w *Workflow) PullDAGRecoveredDevice(ctx context.Context) (DAGRecoveredView, error) {
	return w.updateDAGRecoveredDevice(ctx, nil, DAGOwnerScope{}, true)
}
func (w *Workflow) updateDAGRecoveredDevice(ctx context.Context, r *DAGRecoveryRegistry, scope DAGOwnerScope, refresh bool) (out DAGRecoveredView, err error) {
	if ctx == nil || ctx.Err() != nil {
		return out, context.Canceled
	}
	w.mu.Lock()
	if w.dagResolutionPending() {
		w.mu.Unlock()
		return out, ErrDAGResolutionPending
	}
	if err = w.checkRecoveredDAGNativeLocked(); err != nil {
		w.mu.Unlock()
		return out, err
	}
	if w.dagDeviceCancel != nil || w.dagOwnerCancel != nil || w.dagQueryCancel != nil {
		w.mu.Unlock()
		return out, ErrDAGQueryBusy
	}
	var original recoveryDAGState
	if w.state.RecoveredDAGDevice != nil {
		if err = w.validateRecoveredDAGDeviceLocked(); err != nil {
			w.mu.Unlock()
			return out, err
		}
		original = clone(w.state.RecoveredDAGDevice.Original)
	} else {
		if refresh || w.state.RecoveryDAG == nil || w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil {
			w.mu.Unlock()
			return out, ErrDAGProtectedState
		}
		if err = w.validateDAGStateLocked(); err != nil {
			w.mu.Unlock()
			return out, err
		}
		original = clone(*w.state.RecoveryDAG)
	}
	p, e := w.recoveredDAGOriginalLocked(original)
	if e != nil {
		w.mu.Unlock()
		return out, e
	}
	state, hash, epoch := clone(w.state), w.protectedSHA256, w.engine.State().SessionEpoch
	signing, receiving := bytes.Clone(w.signing), bytes.Clone(w.receiving)
	networkCtx, cancel := context.WithCancel(ctx)
	w.dagDeviceCancel = cancel
	candidate := &Workflow{state: state, signing: signing, receiving: receiving, http: w.http, now: w.now}
	identity := dagOwnerIdentity{Binding: syncclient.DAGJournalBinding{Endpoint: original.Endpoint, AccountID: original.AccountID, AccountGeneration: original.AccountGeneration, OwnerEpoch: original.OwnerEpoch}, DeviceID: original.DeviceID, Signing: original.SigningPublicKey, Receiving: original.ReceivingPublicKey, Snapshot: hash}
	w.mu.Unlock()
	defer func() {
		cancel()
		clear(signing)
		clear(receiving)
		if candidate.verifier != nil {
			candidate.verifier.Close()
		}
		w.mu.Lock()
		w.dagDeviceCancel = nil
		w.mu.Unlock()
	}()
	fail := func(e error) (DAGRecoveredView, error) {
		return DAGRecoveredView{}, errors.Join(syncclient.ErrAcceptedNotApplied, e)
	}
	if err = retireAppliedDAGOwner(r, scope, identity); err != nil {
		return fail(err)
	}
	result, e := syncclient.RecoveredDAGResultFromConfirmedOperation(p)
	if e != nil {
		return fail(e)
	}
	candidate.state.RecoveryDAG = nil
	candidate.state.RecoveryDAGPreparation = nil
	candidate.state.RecoveryDAGRecoveredPreparation = nil
	candidate.state.RecoveredDAGDevice = &recoveredDAGDeviceRecord{Version: 1, Profile: cryptox.RecoveryDAGCapability, Original: original}
	root := recoveredDAGRoot(result)
	candidate.state.Root = &root
	candidate.state.DAGCASRequired = true
	candidate.store = &memoryStore{state: clone(state.Cloud)}
	candidate.engine, err = localstate.New(candidate.store)
	if err != nil {
		return fail(err)
	}
	if state.RecoveredDAGDevice == nil {
		if err = candidate.engine.CompleteEnrollmentAtEpoch(epoch); err != nil {
			return fail(err)
		}
	}
	candidate.verifier, err = candidate.recoveredDAGVerifierLocked()
	if err != nil {
		return fail(err)
	}
	boot, e := syncclient.NewForBoot(syncclient.Config{Endpoint: state.Endpoint, ProtocolMajor: 2, HTTPClient: candidate.http, AccountID: state.AccountID, AccountGeneration: p.AccountGeneration, DeviceID: state.DeviceID, Verifier: candidate.verifier, Engine: candidate.engine, Now: candidate.now})
	if e != nil {
		return fail(e)
	}
	candidate.client, err = boot.BootDevice(networkCtx, signing)
	if err == nil {
		var pulled syncclient.Pull
		pulled, err = candidate.client.Pull(networkCtx)
		if err == nil {
			candidate.state.Grants = []cryptox.SignedGrantWire{}
			for _, g := range pulled.Grants {
				candidate.state.Grants = append(candidate.state.Grants, cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
			}
			cleanDAGLabels(&candidate.state, candidate.engine.State())
			for _, event := range pulled.EnvironmentEvents {
				if e = candidate.rememberLabel(event.Change.Change, event.Sequence); e != nil {
					err = e
					break
				}
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.engine == nil || w.dagPersistenceFailed || w.protectedSHA256 != hash || w.engine.State().SessionEpoch != epoch || w.engine.State().AccountClosed || networkCtx.Err() != nil {
		return fail(errors.Join(ErrDAGProtectedState, networkCtx.Err()))
	}
	if e = w.checkRecoveredDAGNativeLocked(); e != nil {
		return fail(e)
	}
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			logoutErr := w.engine.Logout()
			return fail(errors.Join(err, logoutErr, w.invalidateTrust()))
		}
		return fail(err)
	}
	candidate.state.Cloud = candidate.engine.State()
	// 验证完整候选时仍使用本机旧保护hash作为保存前基点；不能提前安装live状态。
	candidate.saveNativeCAS = w.saveNativeCAS
	candidate.checkNativeState = w.checkNativeState
	candidate.protectedSHA256 = hash
	if e = candidate.validateRecoveredDAGDeviceLocked(); e != nil {
		return fail(e)
	}
	if e = w.saveDAGCandidateLocked(candidate.state); e != nil {
		return fail(e)
	}
	w.store = candidate.store
	w.engine = candidate.engine
	if networkCtx.Err() != nil {
		return fail(networkCtx.Err())
	}
	return w.dagRecoveredViewLocked()
}
