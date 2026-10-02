package main

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/harmonia-vault/core-go/syncclient"
)

func (w *syncWorker) wakeSync() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// 通知只写合并唤醒信号；签名检查、授权投影和普通数据拉取继续使用唯一 network owner。
// 每次重连后无条件补拉，避免握手/断线期间丢通知。独立轮询和本地到期检查始终保留。
func (w *syncWorker) runNotifications() {
	defer close(w.notificationDone)
	failures := uint(0)
	for w.ctx.Err() == nil {
		var subscription *syncclient.NotificationSubscription
		err := w.execute(w.ctx, func(ctx context.Context, client *syncclient.Client) error {
			var err error
			subscription, err = client.OpenNotifications(ctx)
			return err
		})
		received := false
		if err == nil {
			w.wakeSync()
			err = subscription.Watch(w.ctx, func(syncclient.NotificationHint) { received = true; w.wakeSync() })
			subscription.Close()
		}
		if w.ctx.Err() != nil {
			return
		}
		if errors.Is(err, syncclient.ErrTrustInvalidated) {
			w.report(err)
		}
		if errors.Is(err, syncclient.ErrNotificationAuthorization) {
			// 4003 只是重新检查当前授权的信号。Boot 的确定错误才执行清理；不能将任意关闭原因当撤销。
			w.notificationRefresh.Store(true)
			w.wakeSync()
		}
		if received {
			failures = 0
		} else if failures < 6 {
			failures++
		}
		timer := time.NewTimer(notificationRetryDelay(failures))
		select {
		case <-w.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func notificationRetryDelay(failures uint) time.Duration {
	if failures > 6 {
		failures = 6
	}
	delay := time.Second << failures
	if delay > time.Minute {
		delay = time.Minute
	}
	// 退避抖动仅用于连接调度，不用于密钥或协议随机数。
	jittered := time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
	if jittered > time.Minute {
		return time.Minute
	}
	return jittered
}
