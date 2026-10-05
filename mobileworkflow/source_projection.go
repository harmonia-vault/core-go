package mobileworkflow

import (
	"context"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrSourceProjectionPending = errors.New("source projection requires original pending business transaction resolution")

// ApprovalSource 只投影已验证的来源类型与当前可选 Admin 环境，不导出证书、钥匙或签包。
// 它不能替代批准时的在线刷新、明确选择、期限检查和独立系统认证。
type ApprovalSource struct {
	Profile             string   `json:"profile"`
	CertificateVersion  string   `json:"certificateVersion"`
	Checkpoint          uint64   `json:"checkpoint"`
	AdminEnvironmentIDs []string `json:"adminEnvironmentIds"`
}

// TrustedSourceView 是新的有限结果；现有 View/restoreSession ABI 保持不变。
// 当前仅供原生可信调用方使用，尚未加入 Android/profile/Dart capability。
type TrustedSourceView struct {
	Version           int            `json:"version"`
	TrustedDevice     bool           `json:"trustedDevice"`
	AccountID         string         `json:"accountId"`
	AccountGeneration string         `json:"accountGeneration"`
	DeviceID          string         `json:"deviceId"`
	View              View           `json:"view"`
	ApprovalSource    ApprovalSource `json:"approvalSource"`
}

// RestoreSessionWithSource 在同一锁内重验本机来源、期限及缓存，最后持久保存成功才返回。
// 不联网，不代表当前服务器仍准许批准；公开地址或账号登录均不能进入此方法的可信结果。
func (w *Workflow) RestoreSessionWithSource() (TrustedSourceView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return TrustedSourceView{}, err
	}
	return w.sourceViewLocked()
}

// PullWithSource 先沿成熟在线下发验签流收敛，再原子投影同一个 View/checkpoint 的来源。
func (w *Workflow) PullWithSource(ctx context.Context) (TrustedSourceView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return TrustedSourceView{}, err
	}
	if err := w.sourceBusinessGateLocked(); err != nil {
		return TrustedSourceView{}, err
	}
	if err := w.refresh(ctx); err != nil {
		return TrustedSourceView{}, err
	}
	return w.sourceViewLocked()
}

func (w *Workflow) sourceBusinessGateLocked() error {
	for _, record := range w.state.EnvironmentWrites {
		if record == nil {
			return syncclient.ErrWriteJournal
		}
		if !record.Applied {
			return ErrSourceProjectionPending
		}
	}
	if len(w.state.WriteJournal) > 0 {
		if err := w.ensureWriter(); err != nil {
			return err
		}
		items, err := w.writer.PendingRequests()
		if err != nil {
			return err
		}
		for _, item := range items {
			if !item.Applied && !item.Canceled {
				return ErrSourceProjectionPending
			}
		}
	}
	return nil
}

func (w *Workflow) sourceViewLocked() (TrustedSourceView, error) {
	if err := w.sourceBusinessGateLocked(); err != nil {
		return TrustedSourceView{}, err
	}
	if w.state.Root == nil || w.state.Pending != nil || w.state.AccountID == "" || w.engine.State().AccountClosed {
		return TrustedSourceView{}, ErrNotTrusted
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != w.state.AccountGeneration {
		return TrustedSourceView{}, ErrNotTrusted
	}
	if w.state.EnrollmentV5 != nil && (!w.state.EnrollmentV5.Applied || w.state.EnrollmentV5.Sequence == 0) {
		return TrustedSourceView{}, ErrMobileEnrollmentPending
	}
	verifier, err := w.originVerifier()
	if err != nil {
		return TrustedSourceView{}, err
	}
	defer verifier.Close()
	if err = verifier.ValidateStoredIssuerEvidence(w.engine.State().Cloud); err != nil {
		return TrustedSourceView{}, err
	}
	// 到期在 Go 本地引擎内清缓存，再对新的确切状态重验账本。
	if _, err = w.engine.Effective(w.now()); err != nil {
		return TrustedSourceView{}, err
	}
	state := w.engine.State()
	if state.AccountClosed || state.Cloud.AccountID != w.state.AccountID || state.Cloud.AccountGeneration != generation || state.Cloud.Sequence > 9007199254740991 {
		return TrustedSourceView{}, ErrNotTrusted
	}
	if err = verifier.ValidateStoredIssuerEvidence(state.Cloud); err != nil {
		return TrustedSourceView{}, err
	}
	// NewForBoot 不登录、不发送请求；仅将已认证原生来源交给现有 ledger/权限 helper。
	reader, err := syncclient.NewForBoot(syncclient.Config{
		Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID,
		AccountGeneration: generation, DeviceID: w.state.DeviceID, Engine: w.engine,
		Verifier: verifier, Now: w.now,
	})
	if err != nil {
		return TrustedSourceView{}, err
	}
	if _, err = reader.CurrentIssuerDAGEvidence(); err != nil {
		return TrustedSourceView{}, err
	}
	view := w.view()
	source := ApprovalSource{Profile: "issuer-recovery-dag-v1", CertificateVersion: "5", Checkpoint: view.Checkpoint, AdminEnvironmentIDs: []string{}}
	if !state.Paused {
		for _, env := range view.Environments {
			if env.Role != localstate.Admin {
				continue
			}
			_, _, err = reader.PrepareEnrollmentProofV5([]string{env.ID})
			if err != nil {
				return TrustedSourceView{}, err
			}
			source.AdminEnvironmentIDs = append(source.AdminEnvironmentIDs, env.ID)
		}
	}
	result := TrustedSourceView{Version: 1, TrustedDevice: true, AccountID: w.state.AccountID,
		AccountGeneration: w.state.AccountGeneration, DeviceID: w.state.DeviceID,
		View: view, ApprovalSource: source}
	if err = w.persist(); err != nil {
		return TrustedSourceView{}, err
	}
	return result, nil
}
