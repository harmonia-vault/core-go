package main

import (
	"context"
	"errors"
	"sync"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localstate"
)

// accountOwner 只编排 owner 内存任务，不拥有第二份 Store 或网络信任入口。
// Pair 的上下文来自服务而非一次 CLI 连接；Close/Logout 必须等它退出。
type accountOwnerCallbacks struct {
	Login    func(context.Context, localipc.AccountRequest) error
	Pair     func(context.Context, localipc.AccountRequest, uint64, func(string, []byte)) error
	Inspect  func() (localipc.AccountState, error)
	Epoch    func() uint64
	Accepted func() error
}
type ownerPairJob struct {
	cancel    context.CancelFunc
	done      chan struct{}
	ready     chan struct{}
	state     localipc.AccountState
	readyOnce sync.Once
	err       error
}
type accountOwner struct {
	ctx       context.Context
	callbacks accountOwnerCallbacks
	mu        sync.Mutex
	job       *ownerPairJob
	busy      bool
	closed    bool
}

func newAccountOwner(ctx context.Context, c accountOwnerCallbacks) *accountOwner {
	return &accountOwner{ctx: ctx, callbacks: c}
}
func (o *accountOwner) inspect() (localipc.AccountState, error) { return o.callbacks.Inspect() }
func (o *accountOwner) Handle(ctx context.Context, r localipc.AccountRequest) (localipc.AccountState, error) {
	o.mu.Lock()
	if o.closed || o.ctx.Err() != nil {
		o.mu.Unlock()
		return localipc.AccountState{}, localipc.ErrAccountClosed
	}
	switch r.Action {
	case "login":
		if o.job != nil {
			select {
			case <-o.job.done:
				if o.job.state.Phase == "failed" || o.job.state.Phase == "cancelled" {
					o.job = nil
				}
			default:
			}
		}
		if o.busy || o.job != nil {
			o.mu.Unlock()
			return localipc.AccountState{}, localipc.ErrAccountPending
		}
		if len(r.Credential) != 32 {
			o.mu.Unlock()
			return localipc.AccountState{}, localipc.ErrProtocol
		}
		o.busy = true
		o.mu.Unlock()
		err := o.callbacks.Login(ctx, r)
		o.mu.Lock()
		o.busy = false
		o.mu.Unlock()
		if err != nil {
			return localipc.AccountState{}, err
		}
		return localipc.AccountState{Phase: "logged-in"}, nil
	case "pair":
		if o.busy {
			o.mu.Unlock()
			return localipc.AccountState{}, localipc.ErrAccountPending
		}
		if o.job != nil {
			job := o.job
			select {
			case <-job.done:
				if job.state.Phase == "failed" || job.state.Phase == "cancelled" {
					o.job = nil
				} else {
					state := job.state
					o.mu.Unlock()
					return state, nil
				}
			default:
				o.mu.Unlock()
				return o.awaitReady(ctx, job)
			}
		}
		stored, err := o.inspect()
		if err != nil {
			o.mu.Unlock()
			return localipc.AccountState{}, err
		}
		if stored.Accepted {
			o.mu.Unlock()
			return stored, nil
		}
		jobCtx, cancel := context.WithCancel(o.ctx)
		job := &ownerPairJob{cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), state: stored}
		o.job = job
		epoch := o.callbacks.Epoch()
		if stored.Phase == "pending" {
			job.readyOnce.Do(func() { close(job.ready) })
		}
		o.mu.Unlock()
		go o.runPair(jobCtx, job, r, epoch)
		return o.awaitReady(ctx, job)
	case "pair-status":
		job := o.job
		if job != nil {
			if job.state.PairingID != r.PairingID {
				o.mu.Unlock()
				return localipc.AccountState{}, localipc.ErrProtocol
			}
			state := job.state
			o.mu.Unlock()
			// 已接受状态每次复读 owner 元数据；Applied 不由缓存的客户端进度猜测。
			if state.Accepted {
				return o.inspect()
			}
			return state, nil
		}
		state, err := o.inspect()
		o.mu.Unlock()
		if err != nil {
			return localipc.AccountState{}, err
		}
		if state.PairingID != r.PairingID {
			return localipc.AccountState{}, localipc.ErrProtocol
		}
		return state, nil
	case "pair-cancel":
		job := o.job
		if job == nil || job.state.PairingID != r.PairingID {
			o.mu.Unlock()
			return localipc.AccountState{}, localipc.ErrProtocol
		}
		stored, err := o.inspect()
		if err != nil {
			o.mu.Unlock()
			return localipc.AccountState{}, err
		}
		if stored.Phase == "pending" || stored.Accepted {
			o.mu.Unlock()
			return localipc.AccountState{}, localipc.ErrAccountPending
		}
		job.cancel()
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return localipc.AccountState{}, ctx.Err()
		case <-job.done:
		}
		stored, err = o.inspect()
		if err != nil {
			return localipc.AccountState{}, err
		}
		if stored.Phase == "pending" || stored.Accepted {
			return stored, localipc.ErrAccountPending
		}
		o.mu.Lock()
		job.state = localipc.AccountState{Phase: "cancelled", PairingID: r.PairingID}
		o.mu.Unlock()
		return localipc.AccountState{Phase: "cancelled", PairingID: r.PairingID}, nil
	default:
		o.mu.Unlock()
		return localipc.AccountState{}, localipc.ErrProtocol
	}
}
func (o *accountOwner) awaitReady(ctx context.Context, job *ownerPairJob) (localipc.AccountState, error) {
	select {
	case <-ctx.Done():
		return localipc.AccountState{}, ctx.Err()
	case <-job.ready:
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if job.state.PairingID == "" {
		if job.err != nil {
			return localipc.AccountState{}, job.err
		}
		return localipc.AccountState{}, localipc.ErrAccountPending
	}
	return job.state, nil
}
func (o *accountOwner) runPair(ctx context.Context, job *ownerPairJob, r localipc.AccountRequest, epoch uint64) {
	defer close(job.done)
	defer job.readyOnce.Do(func() { close(job.ready) })
	progress := func(id string, code []byte) {
		o.mu.Lock()
		defer o.mu.Unlock()
		job.state = localipc.AccountState{Phase: "pairing", PairingID: id, ShortCode: string(code)}
		job.readyOnce.Do(func() { close(job.ready) })
	}
	err := o.callbacks.Pair(ctx, r, epoch, progress)
	// 旧上下文或 epoch 的结果不可启动新 worker，退出调用方随后清旧 slots。
	if ctx.Err() == nil && o.callbacks.Epoch() == epoch && err == nil {
		err = o.callbacks.Accepted()
	}
	stored, inspectErr := o.inspect()
	o.mu.Lock()
	defer o.mu.Unlock()
	if inspectErr == nil && (stored.Phase == "pending" || stored.Accepted) {
		job.state = stored
		return
	}
	job.err = err
	id := job.state.PairingID
	job.state = localipc.AccountState{Phase: "failed", PairingID: id}
	if errors.Is(err, context.Canceled) {
		job.state.Phase = "cancelled"
	}
}

// stopPair 是 Logout 的 drain：不因 sealed receipt 阻止安全退出账号；它不删除资料。
func (o *accountOwner) stopPair() {
	o.mu.Lock()
	job := o.job
	if job != nil {
		job.cancel()
	}
	o.mu.Unlock()
	if job != nil {
		<-job.done
	}
	o.mu.Lock()
	o.job = nil
	o.mu.Unlock()
}
func (o *accountOwner) Close() { o.mu.Lock(); o.closed = true; o.mu.Unlock(); o.stopPair() }

// daemon任务捕获启动epoch；不能在网络完成后选择logout之后的新epoch。
func protectedEnrollmentEpoch(engine *localstate.Engine, r commandRuntime) uint64 {
	if r.enrollmentEpoch != nil {
		return *r.enrollmentEpoch
	}
	return engine.State().SessionEpoch
}
