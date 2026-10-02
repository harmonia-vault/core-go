package mobileworkflow

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrSelfRevocationPending = errors.New("self-revocation result pending; query the original id before other vault operations")

type SelfRevocationResult struct {
	Completed         bool   `json:"completed"`
	Sequence          uint64 `json:"sequence,omitempty"`
	DeviceInvalidated bool   `json:"deviceInvalidated"`
	AcceptanceUnknown bool   `json:"acceptanceUnknown"`
	Expired           bool   `json:"expired,omitempty"`
}
type SelfRevocationInfo struct {
	State     string `json:"state"`
	ID        string `json:"id,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
}

func (w *Workflow) selfRevocationClient() (*syncclient.Client, error) {
	if w.state.Root == nil {
		return nil, ErrNotTrusted
	}
	generation, err := strconv.ParseUint(w.state.AccountGeneration, 10, 64)
	if err != nil || generation == 0 {
		return nil, ErrNotTrusted
	}
	public := w.signing.Public().(ed25519.PublicKey)
	verifier, err := syncclient.NewPinnedVerifier(syncclient.PinnedTrust{AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, DeviceSigningPublicKey: public, ReceivingPrivateKey: w.receiving, Managers: map[string]ed25519.PublicKey{w.state.DeviceID: public}, Now: w.now})
	if err != nil {
		return nil, err
	}
	return syncclient.NewForBoot(syncclient.Config{Endpoint: w.state.Endpoint, HTTPClient: w.http, AccountID: w.state.AccountID, AccountGeneration: generation, DeviceID: w.state.DeviceID, Engine: w.engine, Verifier: verifier, Now: w.now})
}
func (w *Workflow) restoreSelfRevocation() (*syncclient.SelfRevocationTransaction, error) {
	if len(w.state.SelfRevocation) == 0 {
		return nil, ErrNotTrusted
	}
	var object map[string]any
	if err := decode(w.state.SelfRevocation, &object); err != nil {
		return nil, errors.New("protected self-revocation JSON invalid")
	}
	client, err := w.selfRevocationClient()
	if err != nil {
		return nil, err
	}
	return client.RestoreSelfRevocation(w.state.SelfRevocation)
}

// 纯元数据允许pending时调用，不返回缓存、token或签包。
func (w *Workflow) SelfRevocationInfo() (SelfRevocationInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return SelfRevocationInfo{}, ErrClosed
	}
	if len(w.state.SelfRevocation) == 0 {
		return SelfRevocationInfo{State: "none"}, nil
	}
	transaction, err := w.restoreSelfRevocation()
	if err != nil {
		return SelfRevocationInfo{}, err
	}
	state := "pending"
	if transaction.ExpiresAt() <= w.now().Unix() {
		state = "expired-pending"
	}
	return SelfRevocationInfo{State: state, ID: transaction.ID(), ExpiresAt: transaction.ExpiresAt()}, nil
}
func (w *Workflow) selfInvalidated(err error) (SelfRevocationResult, error) {
	result := SelfRevocationResult{DeviceInvalidated: true, AcceptanceUnknown: true}
	if !w.closed {
		err = errors.Join(err, w.invalidateTrust())
	}
	return result, err
}
func (w *Workflow) selfKnownComplete(sequence uint64) (SelfRevocationResult, error) {
	result := SelfRevocationResult{Completed: true, Sequence: sequence, DeviceInvalidated: true}
	if err := w.engine.Logout(); err != nil {
		return result, err
	}
	return result, w.invalidateTrust()
}

// RevokeSelf只接受一个已确认根手机、当前全部环境Admin的自撤销意图。
// 未知接受结果留同一个密封事务；不换id、不换签包、不把boot403假报为原请求完成。
func (w *Workflow) RevokeSelf(ctx context.Context, id string) (SelfRevocationResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return SelfRevocationResult{}, ErrClosed
	}
	if len(id) > 64 || !identifier.MatchString(id) {
		return SelfRevocationResult{}, errors.New("self-revocation request id invalid")
	}
	var transaction *syncclient.SelfRevocationTransaction
	var err error
	if len(w.state.SelfRevocation) == 0 {
		if err = w.refresh(ctx); err != nil {
			return SelfRevocationResult{}, err
		}
		transaction, err = w.client.PrepareSelfRevocation(ctx, id, w.signing)
		if err != nil {
			return SelfRevocationResult{}, err
		}
		w.state.SelfRevocation, err = transaction.ProtectedBytes()
		if err != nil {
			return SelfRevocationResult{}, err
		}
	} else {
		transaction, err = w.restoreSelfRevocation()
		if err != nil {
			return SelfRevocationResult{}, err
		}
		if transaction.ID() != id {
			return SelfRevocationResult{}, syncclient.ErrWriteConflict
		}
	}
	// 即使上一次native Save失败，同一实例重试也必须先重新真正密封完成。
	if err = w.persist(); err != nil {
		return SelfRevocationResult{}, err
	}
	result := SelfRevocationResult{AcceptanceUnknown: true}
	if transaction.ExpiresAt() <= w.now().Unix() {
		transaction.DiscardExpiredToken()
		w.state.SelfRevocation, err = transaction.ProtectedBytes()
		if err != nil {
			return result, err
		}
		if err = w.persist(); err != nil {
			return result, err
		}
		if err = w.boot(ctx); err != nil {
			if errors.Is(err, syncclient.ErrTrustInvalidated) {
				return w.selfInvalidated(err)
			}
			return result, errors.Join(ErrSelfRevocationPending, err)
		}
		status, err := transaction.QueryThrough(ctx, w.client)
		if err != nil {
			return result, errors.Join(ErrSelfRevocationPending, err)
		}
		if status.State == "complete" {
			return w.selfKnownComplete(status.Sequence)
		}
		// 本地壁钟到期不能证明服务器/在途请求从未接受；保留无bearer的pending gate。
		return SelfRevocationResult{Expired: true, AcceptanceUnknown: true}, syncclient.ErrSelfRevocationExpired
	}
	status, err := transaction.Query(ctx)
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return w.selfInvalidated(err)
		}
		var fault *syncclient.RequestError
		if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
			if err = w.boot(ctx); err != nil {
				if errors.Is(err, syncclient.ErrTrustInvalidated) {
					return w.selfInvalidated(err)
				}
				return result, errors.Join(ErrSelfRevocationPending, err)
			}
			// 新boot只查原id；原token失效不重签、不将原挑战改绑新session。
			newer, queryErr := transaction.QueryThrough(ctx, w.client)
			if queryErr == nil && newer.State == "complete" {
				return w.selfKnownComplete(newer.Sequence)
			}
			return result, errors.Join(ErrSelfRevocationPending, queryErr)
		}
		return result, errors.Join(ErrSelfRevocationPending, err)
	}
	if status.State == "complete" {
		return w.selfKnownComplete(status.Sequence)
	}
	if status.State == "unknown" {
		return result, ErrSelfRevocationPending
	}
	if err = transaction.RefreshOriginalAuthorities(ctx); err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return w.selfInvalidated(err)
		}
		return result, errors.Join(ErrSelfRevocationPending, err)
	}
	// 拉取产生的当前权限检查点也必须在真正POST之前落盘。
	if err = w.persist(); err != nil {
		return result, err
	}
	accepted, err := transaction.Submit(ctx)
	if err != nil {
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			return w.selfInvalidated(err)
		}
		return result, errors.Join(ErrSelfRevocationPending, err)
	}
	return w.selfKnownComplete(accepted.Sequence)
}
