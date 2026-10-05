package mobileworkflow

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrDAGAuthorizationNotPersisted = errors.New("verified safety authorization could not be durably saved")

// dagWriteJournal单独绑定已应用登记来源；不能把旧普通WriteJournal提升为P4。
type dagWriteJournal struct {
	Version        int    `json:"version"`
	Profile        string `json:"profile"`
	EnrollmentID   string `json:"enrollmentId"`
	EnrollmentHash string `json:"enrollmentHash"`
	Log            []byte `json:"log"`
}

func (r *dagWriteJournal) UnmarshalJSON(raw []byte) error {
	if exactDAGObject(raw, "version", "profile", "enrollmentId", "enrollmentHash", "log") != nil {
		return ErrDAGProtectedState
	}
	type plain dagWriteJournal
	var out plain
	if decode(raw, &out) != nil {
		return ErrDAGProtectedState
	}
	*r = dagWriteJournal(out)
	return nil
}

type dagReadonlyWriteLog struct{ data []byte }

func (j dagReadonlyWriteLog) Load() ([]byte, error) {
	if len(j.data) == 0 {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(j.data), nil
}
func (j dagReadonlyWriteLog) Save([]byte) error { return ErrDAGProtectedState }

func (w *Workflow) validateDAGWritesLocked() error {
	r := w.state.DAGWrites
	if r == nil {
		return nil
	}
	if w.state.RecoveredDAGDevice == nil || r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || len(r.Log) == 0 || len(r.Log) > 8<<20 {
		return ErrDAGProtectedState
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil || r.EnrollmentID != p.OperationID || r.EnrollmentHash != p.ContentHash {
		return ErrDAGProtectedState
	}
	writer, e := syncclient.NewWriter(w.state.AccountID, p.AccountGeneration, w.state.DeviceID, w.engine.State().SessionEpoch, w.signing, dagReadonlyWriteLog{r.Log})
	if e != nil {
		return errors.Join(ErrDAGProtectedState, e)
	}
	defer writer.Close()
	_, e = writer.PendingRequests()
	return e
}

// DAGWriteResult的View仅在当前P4下发、整份native CAS与最后postcheck都成功后返回。
type DAGWriteResult struct {
	Write syncclient.WriteResult `json:"write"`
	View  *DAGRecoveredView      `json:"view,omitempty"`
}

func (w *Workflow) PendingDAGWrites() ([]syncclient.WriteOperationInfo, error) {
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
	if w.state.DAGWrites == nil {
		return []syncclient.WriteOperationInfo{}, nil
	}
	p, e := w.recoveredDAGOriginalLocked(w.state.RecoveredDAGDevice.Original)
	if e != nil {
		return nil, e
	}
	writer, e := syncclient.NewWriter(w.state.AccountID, p.AccountGeneration, w.state.DeviceID, w.engine.State().SessionEpoch, w.signing, dagReadonlyWriteLog{w.state.DAGWrites.Log})
	if e != nil {
		return nil, e
	}
	defer writer.Close()
	return writer.PendingRequests()
}

func (w *Workflow) SetDAGVariable(ctx context.Context, env, name, value, id string) (DAGWriteResult, error) {
	return w.runDAGWrite(ctx, syncclient.WriteRequest{ID: id, Operation: "put", EnvironmentID: env, Name: name, Value: value})
}
func (w *Workflow) DeleteDAGVariable(ctx context.Context, env, name, id string) (DAGWriteResult, error) {
	return w.runDAGWrite(ctx, syncclient.WriteRequest{ID: id, Operation: "delete", EnvironmentID: env, Name: name})
}
func (w *Workflow) RetryDAGWrite(ctx context.Context, id string) (DAGWriteResult, error) {
	return w.runDAGWrite(ctx, syncclient.WriteRequest{ID: id, Operation: "retry"})
}

// 独立candidate的网络不持原Workflow锁；唯一原生日志保存点仍由原owner的hash/epoch/CAS串行。
type dagActiveWriteLog struct {
	owner, candidate *Workflow
	ctx              context.Context
	hash             string
	epoch            uint64
	terminalCause    error
	canceledSafety   bool
	commits          uint64
}

func (j *dagActiveWriteLog) Load() ([]byte, error) {
	if j.candidate.state.DAGWrites == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(j.candidate.state.DAGWrites.Log), nil
}
func (j *dagActiveWriteLog) Save(raw []byte) error {
	if j.ctx.Err() != nil {
		return j.ctx.Err()
	}
	// Writer自己的Pull可推进candidate。每次保存再通过相同验证器取得完整当前grants/labels，
	// 不能让旧签授权metadata与新Cloud检查点混存，尤其并发降权/撤销。
	if e := j.candidate.pullDAGBusiness(j.ctx); e != nil {
		if errors.Is(e, syncclient.ErrTrustInvalidated) || errors.Is(e, ErrDAGAuthorizationNotPersisted) {
			j.terminalCause = e
		}
		return e
	}
	p, e := j.candidate.recoveredDAGOriginalLocked(j.candidate.state.RecoveredDAGDevice.Original)
	if e != nil {
		return e
	}
	j.candidate.state.DAGWrites = &dagWriteJournal{Version: 1, Profile: cryptox.RecoveryDAGCapability, EnrollmentID: p.OperationID, EnrollmentHash: p.ContentHash, Log: bytes.Clone(raw)}
	return j.commitCandidate()
}

// 已接收的权威安全状态独立保存，不能依赖之后prepare或journal.Save是否会执行。
func (j *dagActiveWriteLog) commitVerifiedPull(ctx context.Context, p syncclient.Pull) (err error) {
	if ctx != j.ctx {
		return syncclient.ErrVerifiedPullCommitScope
	}
	priorCommit, safetyAttempted := j.commits, false
	defer func() {
		if err != nil && ctx.Err() != nil && j.commits == priorCommit && !safetyAttempted {
			err = errors.Join(err, j.commitCanceledSafety(p))
		}
	}()
	if ctx.Err() != nil {
		safetyAttempted = true
		return j.commitCanceledSafety(p)
	}
	j.candidate.state.Grants = []cryptox.SignedGrantWire{}
	for _, g := range p.Grants {
		j.candidate.state.Grants = append(j.candidate.state.Grants, cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
	}
	cleanDAGLabels(&j.candidate.state, j.candidate.engine.State())
	// 授权投影只处理安全变化；不会应用rotation标签或未来dataSequence。
	if p.Scope != "authorizations" {
		for _, event := range p.EnvironmentEvents {
			if e := j.candidate.rememberLabel(event.Change.Change, event.Sequence); e != nil {
				return e
			}
		}
	}
	return j.commitCandidate()
}
func (j *dagActiveWriteLog) commitCandidate() error {
	if j.ctx.Err() != nil && !j.canceledSafety {
		return j.ctx.Err()
	}
	j.candidate.state.Cloud = j.candidate.engine.State()
	o := j.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.engine == nil || o.dagPersistenceFailed || o.protectedSHA256 != j.hash || o.engine.State().SessionEpoch != j.epoch || o.engine.State().AccountClosed || j.ctx.Err() != nil && !j.canceledSafety {
		return ErrDAGProtectedState
	}
	if e := o.checkRecoveredDAGNativeLocked(); e != nil {
		return e
	}
	j.candidate.saveNativeCAS = o.saveNativeCAS
	j.candidate.checkNativeState = o.checkNativeState
	j.candidate.protectedSHA256 = j.hash
	if e := j.candidate.validateRecoveredDAGDeviceLocked(); e != nil {
		return e
	}
	// 单次完整clone先生成可安装的Engine，CAS失败不能提前替换live来源。
	store := &memoryStore{state: clone(j.candidate.state.Cloud)}
	engine, e := localstate.New(store)
	if e != nil {
		return e
	}
	if j.ctx.Err() != nil && !j.canceledSafety {
		return j.ctx.Err()
	}
	if e = o.saveDAGCandidateLocked(clone(j.candidate.state)); e != nil {
		return e
	}
	o.store, o.engine = store, engine
	j.commits++
	j.hash = o.protectedSHA256
	j.candidate.protectedSHA256 = j.hash
	if j.canceledSafety {
		return nil
	}
	return j.ctx.Err()
}

// 仅已经过完整成熟验签且Engine接受的response可进入此取消窗口。
// WithoutCancel只用于本机授权投影验签，没有HTTP、新挑战或续期。
func (j *dagActiveWriteLog) commitCanceledSafety(p syncclient.Pull) error {
	o := j.owner
	o.mu.Lock()
	if !j.sameOwnerLocked() {
		o.mu.Unlock()
		return ErrDAGProtectedState
	}
	prior := clone(o.engine.State())
	priorState := clone(o.state)
	o.mu.Unlock()
	p.Scope, p.Events = "authorizations", nil
	verified, e := j.candidate.verifier.VerifyAuthorizationRefresh(context.WithoutCancel(j.ctx), p, prior.Cloud)
	if e != nil {
		return errors.Join(j.ctx.Err(), e)
	}
	if !dagAuthorizationBecameSafer(prior.Cloud, verified, j.candidate.now()) {
		return j.ctx.Err()
	}
	store := &memoryStore{state: prior}
	engine, e := localstate.New(store)
	if e != nil {
		return e
	}
	if e = engine.AcceptAuthorizationRefreshAtEpoch(verified, j.candidate.now(), j.epoch); e != nil {
		return e
	}
	j.candidate.store, j.candidate.engine = store, engine
	j.candidate.state = priorState
	j.candidate.state.Grants = []cryptox.SignedGrantWire{}
	for _, g := range p.Grants {
		j.candidate.state.Grants = append(j.candidate.state.Grants, cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
	}
	cleanDAGLabels(&j.candidate.state, engine.State())
	j.canceledSafety = true
	e = j.commitCandidate()
	j.canceledSafety = false
	if e != nil {
		o.mu.Lock()
		same := j.sameOwnerLocked()
		o.mu.Unlock()
		if same {
			j.terminalCause = errors.Join(ErrDAGAuthorizationNotPersisted, e)
			return j.terminalCause
		}
		return ErrDAGProtectedState
	}
	return j.ctx.Err()
}
func (j *dagActiveWriteLog) sameOwnerLocked() bool {
	o := j.owner
	return !o.closed && o.engine != nil && o.protectedSHA256 == j.hash && o.engine.State().SessionEpoch == j.epoch && !o.engine.State().AccountClosed
}
func dagAuthorizationBecameSafer(before, after localstate.CloudSnapshot, now time.Time) bool {
	rank := func(r localstate.Role) int {
		switch r {
		case localstate.Admin:
			return 3
		case localstate.ReadWrite:
			return 2
		case localstate.ReadOnly:
			return 1
		}
		return 0
	}
	for id, old := range before.Environments {
		next, exists := after.Environments[id]
		if !exists || rank(next.Role) < rank(old.Role) {
			return true
		}
		if next.ExpiresAt != nil && (old.ExpiresAt == nil || next.ExpiresAt.Before(*old.ExpiresAt) || !now.Before(*next.ExpiresAt)) {
			return true
		}
	}
	return false
}

func (w *Workflow) pullDAGBusiness(ctx context.Context) error {
	_, e := w.client.Pull(ctx)
	return e
}

func (w *Workflow) runDAGWrite(ctx context.Context, in syncclient.WriteRequest) (out DAGWriteResult, err error) {
	if e := syncclient.ValidateWriteRequest(in); e != nil {
		return out, e
	}
	if in.Operation != "put" && in.Operation != "delete" && in.Operation != "retry" {
		return out, syncclient.ErrWriteInput
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
	if e := w.validateRecoveredDAGDeviceLocked(); e != nil {
		w.mu.Unlock()
		return out, e
	}
	if w.engine.State().Paused {
		w.mu.Unlock()
		return out, syncclient.ErrPaused
	}
	if w.approvalV5Pending() {
		w.mu.Unlock()
		return out, ErrApprovalPending
	}
	if w.dagManagementPending() {
		w.mu.Unlock()
		return out, ErrManagementPending
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
	journal := &dagActiveWriteLog{owner: w, candidate: candidate, ctx: networkCtx, hash: hash, epoch: epoch}
	defer func() {
		err = errors.Join(err, journal.terminalCause)
		cancel()
		clear(signing)
		clear(receiving)
		if candidate.verifier != nil {
			candidate.verifier.Close()
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.dagDeviceCancel = nil
		if (errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, ErrDAGAuthorizationNotPersisted)) && !w.closed && w.engine != nil && w.protectedSHA256 == journal.hash && w.engine.State().SessionEpoch == epoch {
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
	candidate.client, err = candidate.client.WithVerifiedPullCommit(networkCtx, journal.commitVerifiedPull)
	if err != nil {
		return out, err
	}
	if err = candidate.pullDAGBusiness(networkCtx); err != nil {
		return out, err
	}
	writer, e := syncclient.NewWriter(state.AccountID, p.AccountGeneration, state.DeviceID, epoch, signing, journal)
	if e != nil {
		return out, e
	}
	defer writer.Close()
	out.Write, err = writer.Execute(networkCtx, candidate.client, in)
	if err != nil {
		out.Write.Applied = false
		return out, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.engine == nil || w.dagPersistenceFailed || w.protectedSHA256 != journal.hash || w.engine.State().SessionEpoch != epoch || networkCtx.Err() != nil {
		out.Write.Applied = false
		return out, ErrDAGProtectedState
	}
	if err = w.validateRecoveredDAGDeviceLocked(); err != nil {
		out.Write.Applied = false
		return out, err
	}
	view, e := w.dagRecoveredViewLocked()
	if e != nil {
		out.Write.Applied = false
		return out, e
	}
	out.View = &view
	return out, nil
}
