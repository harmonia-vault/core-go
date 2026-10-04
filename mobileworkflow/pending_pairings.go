package mobileworkflow

import (
	"context"
	"errors"

	"github.com/harmonia-vault/core-go/syncclient"
)

// 每次前台显式刷新都先成熟持钥Boot和当前完整Pull，不复用登录token或离线Admin。
func (w *Workflow) pendingPairingRequests(ctx context.Context, version string) (syncclient.PendingPairingRequests, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return syncclient.PendingPairingRequests{}, ErrClosed
	}
	if e := w.check(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if e := w.boot(ctx); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if e := w.refreshForApproval(ctx); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	var out syncclient.PendingPairingRequests
	var e error
	if version == "3" {
		out, e = w.client.PendingPairingRequestsV3(ctx)
	} else if version == "4" {
		out, e = w.client.PendingPairingRequestsV4(ctx)
	} else {
		return out, ErrUnsupported
	}
	if e != nil {
		if errors.Is(e, syncclient.ErrTrustInvalidated) {
			return syncclient.PendingPairingRequests{}, errors.Join(e, w.invalidateTrust())
		}
		return syncclient.PendingPairingRequests{}, e
	}
	if e = ctx.Err(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	if e = w.check(); e != nil {
		return syncclient.PendingPairingRequests{}, e
	}
	return out, nil
}
func (w *Workflow) PendingPairingRequestsV3(ctx context.Context) (syncclient.PendingPairingRequests, error) {
	return w.pendingPairingRequests(ctx, "3")
}
func (w *Workflow) PendingPairingRequestsV4(ctx context.Context) (syncclient.PendingPairingRequests, error) {
	return w.pendingPairingRequests(ctx, "4")
}
