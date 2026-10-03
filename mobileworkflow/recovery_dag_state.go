package mobileworkflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrDAGProtectedState = errors.New("mobile DAG protected owner or original journal unavailable")
var ErrDAGAtomicStoreRequired = errors.New("mobile DAG requires native whole-state atomic compare-and-swap")

func protectedStateHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

var ErrDAGPersistence = errors.New("mobile DAG native persistence failed; reopen authenticated owner")

// S1 仅保存已密封原包，没有 session、seed、恢复码、私钥或设备可信位。
// profile/owner 与整个已认证 Workflow 互相绑定，不能和旧业务来源混用。
type recoveryDAGState struct {
	Version            int             `json:"version"`
	Profile            string          `json:"profile"`
	Endpoint           string          `json:"endpoint"`
	AccountID          string          `json:"accountId"`
	AccountGeneration  uint64          `json:"accountGeneration"`
	DeviceID           string          `json:"deviceId"`
	SigningPublicKey   string          `json:"signingPublicKey"`
	ReceivingPublicKey string          `json:"receivingPublicKey"`
	OwnerEpoch         uint64          `json:"ownerEpoch"`
	Journal            json.RawMessage `json:"journal"`
}

// RecoveryDAGPendingInfo 只投影原保护记录。没有查询就只能 unknown，
// 核心 Applied 不代表手机 Boot/Pull 或最终密封完成。S1 不连接 native ABI。
type RecoveryDAGPendingInfo struct {
	Version          int    `json:"version"`
	Profile          string `json:"profile"`
	State            string `json:"state"`
	OperationID      string `json:"operationId,omitempty"`
	Kind             string `json:"kind,omitempty"`
	ContentHash      string `json:"contentHash,omitempty"`
	Acceptance       string `json:"acceptance"`
	AcceptedSequence uint64 `json:"acceptedSequence,omitempty"`
	OriginalApplied  bool   `json:"originalApplied"`
	TrustedDevice    bool   `json:"trustedDevice"`
}

// 只能从当前 Workflow 取得，Close/Logout 后所有方法失败；不能跨认证保存此 adapter。
// 方法自己取得 Workflow 锁，调用方不得持有 w.mu；S2 活 session 只能经单次 lease 使用。
type mobileDAGStore struct {
	workflow                                       *Workflow
	binding                                        syncclient.DAGJournalBinding
	deviceID, signingPublicKey, receivingPublicKey string
}

func (w *Workflow) dagBindingLocked() (syncclient.DAGJournalBinding, error) {
	if w.closed || w.engine == nil {
		return syncclient.DAGJournalBinding{}, ErrClosed
	}
	if w.dagPersistenceFailed {
		return syncclient.DAGJournalBinding{}, ErrDAGPersistence
	}
	if w.saveNativeCAS == nil || w.checkNativeState == nil {
		return syncclient.DAGJournalBinding{}, ErrDAGAtomicStoreRequired
	}
	if err := w.checkNativeState(w.protectedSHA256); err != nil {
		w.dagPersistenceFailed = true
		return syncclient.DAGJournalBinding{}, errors.Join(ErrDAGProtectedState, err)
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != w.state.AccountGeneration || !identifier.MatchString(w.state.AccountID) {
		return syncclient.DAGJournalBinding{}, ErrDAGProtectedState
	}
	state := w.engine.State()
	if state.Synthetic || state.AccountClosed || state.Cloud.AccountID != "" || w.state.Root != nil || w.state.Pending != nil || w.state.Recovery != nil || w.state.RecoveryAuthority != nil || w.state.RecoveredDevice != nil || w.state.EnrollmentV3 != nil || w.state.PendingApproval != nil || w.state.PendingApprovalV3 != nil || w.state.PendingApprovalV4 != nil || w.state.Management != nil || len(w.state.SelfRevocation) > 0 || len(w.state.WriteJournal) > 0 || len(w.state.EnvironmentWrites) > 0 || len(w.state.InitialAuthorities) > 0 || len(w.state.Grants) > 0 || len(w.state.Labels) > 0 {
		return syncclient.DAGJournalBinding{}, ErrDAGProtectedState
	}
	return syncclient.DAGJournalBinding{Endpoint: w.state.Endpoint, AccountID: w.state.AccountID, AccountGeneration: generation, OwnerEpoch: state.SessionEpoch}, nil
}
func (w *Workflow) validateDAGStateLocked() error {
	r := w.state.RecoveryDAG
	if r == nil {
		return nil
	}
	b, err := w.dagBindingLocked()
	if err != nil {
		return err
	}
	if r.Version != 1 || r.Profile != cryptox.RecoveryDAGCapability || r.Endpoint != b.Endpoint || r.AccountID != b.AccountID || r.AccountGeneration != b.AccountGeneration || r.OwnerEpoch != b.OwnerEpoch || r.DeviceID != w.state.DeviceID || r.SigningPublicKey != w.state.SigningPublicKey || r.ReceivingPublicKey != w.state.ReceivingPublicKey {
		return ErrDAGProtectedState
	}
	p, err := syncclient.DecodeDAGJournal(b, r.Journal)
	if err != nil {
		return err
	}
	return w.validateDAGDeviceLocked(p)
}
func (w *Workflow) validateDAGDeviceLocked(p syncclient.ProtectedDAGOperation) error {
	if p.Recovered != nil {
		e := p.Recovered.Submission.Enrollment
		if e.DeviceID != w.state.DeviceID || e.DeviceSigningPublicKey != w.state.SigningPublicKey || e.DeviceReceivingPublicKey != w.state.ReceivingPublicKey {
			return ErrDAGProtectedState
		}
	}
	return nil
}
func (s mobileDAGStore) ownerLocked(b syncclient.DAGJournalBinding) error {
	current, err := s.workflow.dagBindingLocked()
	if err != nil {
		return err
	}
	if b != s.binding || current != s.binding || s.workflow.state.DeviceID != s.deviceID || s.workflow.state.SigningPublicKey != s.signingPublicKey || s.workflow.state.ReceivingPublicKey != s.receivingPublicKey {
		return ErrDAGProtectedState
	}
	return s.workflow.validateDAGStateLocked()
}
func (s mobileDAGStore) LoadDAGJournal(b syncclient.DAGJournalBinding) ([]byte, error) {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := s.ownerLocked(b); err != nil {
		return nil, err
	}
	if w.state.RecoveryDAG == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(w.state.RecoveryDAG.Journal), nil
}
func (s mobileDAGStore) CompareAndSwapDAGJournal(b syncclient.DAGJournalBinding, old, next []byte) error {
	w := s.workflow
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := s.ownerLocked(b); err != nil {
		return err
	}
	var previous []byte
	if w.state.RecoveryDAG != nil {
		previous = w.state.RecoveryDAG.Journal
	}
	if !syncclient.EqualDAGJournalBytes(previous, old) {
		return syncclient.ErrDAGJournalConflict
	}
	p, err := syncclient.DecodeDAGJournal(b, next)
	if err != nil {
		return err
	}
	if err = w.validateDAGDeviceLocked(p); err != nil {
		return err
	}
	candidate := clone(w.state)
	candidate.Cloud = w.engine.State()
	candidate.RecoveryDAG = &recoveryDAGState{Version: 1, Profile: cryptox.RecoveryDAGCapability, Endpoint: b.Endpoint, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, DeviceID: w.state.DeviceID, SigningPublicKey: w.state.SigningPublicKey, ReceivingPublicKey: w.state.ReceivingPublicKey, OwnerEpoch: b.OwnerEpoch, Journal: bytes.Clone(next)}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if len(encoded) > 8<<20 {
		return ErrDAGProtectedState
	}
	if err = w.saveNativeCAS(w.protectedSHA256, encoded); err != nil {
		// 失败不能推进 RAM，也不能在 callback 内 Close 活 session。bridge 先失效
		// lease/cancel context，再由最外层操作解锁后 retire；此对象拒绝后续保存。
		w.dagPersistenceFailed = true
		return errors.Join(ErrDAGPersistence, err)
	}
	w.state = candidate
	w.protectedSHA256 = protectedStateHash(encoded)
	return nil
}

// 仅 Go 高层内部使用；S1 没有导出方法接收外部 signed packet 或生成 live session。
func (w *Workflow) newRecoveryDAGJournal() (*syncclient.CheckedDAGJournal, error) {
	w.mu.Lock()
	b, err := w.dagBindingLocked()
	s := mobileDAGStore{workflow: w, binding: b, deviceID: w.state.DeviceID, signingPublicKey: w.state.SigningPublicKey, receivingPublicKey: w.state.ReceivingPublicKey}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return syncclient.NewCheckedDAGJournal(s, b)
}
func (w *Workflow) RecoveryDAGPendingInfo() (RecoveryDAGPendingInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	info := RecoveryDAGPendingInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "none", Acceptance: "unknown"}
	if w.closed {
		return info, ErrClosed
	}
	if w.dagPersistenceFailed {
		return info, ErrDAGPersistence
	}
	if w.state.RecoveryDAG == nil {
		return info, nil
	}
	if err := w.validateDAGStateLocked(); err != nil {
		return info, err
	}
	b, err := w.dagBindingLocked()
	if err != nil {
		return info, err
	}
	p, err := syncclient.DecodeDAGJournal(b, w.state.RecoveryDAG.Journal)
	if err != nil {
		return info, err
	}
	info.State = "pending"
	info.OperationID, info.Kind, info.ContentHash = p.OperationID, p.Kind, p.ContentHash
	info.AcceptedSequence, info.OriginalApplied = p.AcceptedSequence, p.Applied
	if p.AcceptedSequence != 0 {
		info.State = "accepted-original"
		info.Acceptance = "accepted"
	}
	return info, nil
}
