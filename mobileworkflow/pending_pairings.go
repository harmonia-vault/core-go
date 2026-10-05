package mobileworkflow

import (
	"context"
	"errors"

	"github.com/harmonia-vault/core-go/syncclient"
)

// 每次前台显式刷新都先成熟持钥Boot和当前完整Pull，不复用登录token或离线Admin。
func (w *Workflow) PendingPairingRequestsV5(ctx context.Context) (syncclient.PendingPairingRequests, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return syncclient.PendingPairingRequests{}, ErrClosed
	}
	if e := w.approvalGateV5(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if w.approvalV5Pending() {
		return syncclient.PendingPairingRequests{}, ErrApprovalPending
	}
	if e := w.boot(ctx); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if e := w.refreshForApproval(ctx); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	out, e := w.client.PendingPairingRequestsV5(ctx)
	if e != nil {
		if errors.Is(e, syncclient.ErrTrustInvalidated) {
			return syncclient.PendingPairingRequests{}, errors.Join(e, w.invalidateTrust())
		}
		return syncclient.PendingPairingRequests{}, e
	}
	if e = ctx.Err(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if e = w.approvalGateV5(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	return out, nil
}
