package mobileworkflow

import (
	"context"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/syncclient"
)

type DAGAccountScopeInfo struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	DeviceID          string `json:"deviceId"`
	TrustedDevice     bool   `json:"trustedDevice"`
}

// LoginDAGAccountScope只持久未可信本机账号范围，不存login bearer/hash/code/seed。
// 原账号/代际不能替换；后续恢复owner始终使用此同一whole-state CAS基点。
func (w *Workflow) LoginDAGAccountScope(ctx context.Context, email, password string) (out DAGAccountScopeInfo, err error) {
	w.mu.Lock()
	defer func() {
		w.mu.Unlock()
		if errors.Is(err, ErrDAGPersistence) {
			w.Close()
		}
	}()
	if w.closed || w.engine == nil {
		return out, ErrClosed
	}
	if w.dagPersistenceFailed {
		return out, ErrDAGPersistence
	}
	if w.saveNativeCAS == nil || w.checkNativeState == nil {
		return out, ErrDAGAtomicStoreRequired
	}
	// 仅账号范围可已存在，所有旧信任或未完成原包禁止借登录替换。
	cloud := w.engine.State()
	if w.dagOwnerCancel != nil || w.dagQueryCancel != nil || w.state.Root != nil || w.state.Pending != nil || w.state.RecoveryDAG != nil || w.state.RecoveryDAGPreparation != nil || w.state.RecoveryDAGRecoveredPreparation != nil || w.state.Recovery != nil || w.state.RecoveryAuthority != nil || w.state.RecoveredDevice != nil || w.state.EnrollmentV3 != nil || w.state.PendingApproval != nil || w.state.PendingApprovalV3 != nil || w.state.PendingApprovalV4 != nil || w.state.Management != nil || len(w.state.SelfRevocation) > 0 || len(w.state.WriteJournal) > 0 || len(w.state.EnvironmentWrites) > 0 || len(w.state.InitialAuthorities) > 0 || len(w.state.Grants) > 0 || len(w.state.Labels) > 0 || cloud.Synthetic || cloud.AccountClosed || cloud.Cloud.AccountID != "" || len(cloud.Cloud.Environments) > 0 || len(cloud.Originals) > 0 || len(cloud.Managed) > 0 {
		return out, ErrDAGProtectedState
	}
	if (w.state.AccountID == "") != (w.state.AccountGeneration == "") {
		return out, ErrDAGProtectedState
	}
	if w.state.AccountID != "" {
		gen, e := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
		if e != nil || gen == 0 || strconv.FormatUint(gen, 10) != w.state.AccountGeneration || !identifier.MatchString(w.state.AccountID) {
			return out, ErrDAGProtectedState
		}
	}
	closeFailed := func(err error) (DAGAccountScopeInfo, error) {
		w.dagPersistenceFailed = true
		if w.dagOwnerCancel != nil {
			w.dagOwnerCancel()
		}
		if w.dagQueryCancel != nil {
			w.dagQueryCancel()
		}
		return DAGAccountScopeInfo{}, errors.Join(ErrDAGPersistence, err)
	}
	if err := w.checkNativeState(w.protectedSHA256); err != nil {
		return closeFailed(err)
	}
	value, err := credential(password)
	if err != nil {
		return out, err
	}
	result, err := syncclient.Login(ctx, syncclient.LoginConfig{Endpoint: w.state.Endpoint, HTTPClient: w.http, Email: email, Credential: value, Now: w.now})
	value = ""
	if err != nil {
		return out, err
	}
	result.Token = "" // 登录随机会话不用于恢复，也不留RAM/持久state。
	if w.state.AccountID != "" && (result.AccountID != w.state.AccountID || result.AccountGeneration != w.state.AccountGeneration) {
		return out, ErrDAGOwnerBinding
	}
	if ctx == nil || ctx.Err() != nil {
		return out, context.Canceled
	}
	candidate := clone(w.state)
	candidate.Cloud = cloud
	candidate.AccountID = result.AccountID
	candidate.AccountGeneration = result.AccountGeneration
	if err = w.saveDAGCandidateLocked(candidate); err != nil {
		return closeFailed(err)
	}
	w.login = nil
	return DAGAccountScopeInfo{AccountID: result.AccountID, AccountGeneration: result.AccountGeneration, DeviceID: w.state.DeviceID}, nil
}
