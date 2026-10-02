package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

type protectedWriteJournal struct{ vault *localkeys.Vault }

func (j protectedWriteJournal) Load() ([]byte, error)  { return j.vault.Load("writes-v1") }
func (j protectedWriteJournal) Save(data []byte) error { return j.vault.Save("writes-v1", data) }

type syncWorker struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	done                chan struct{}
	notificationDone    chan struct{}
	wake                chan struct{}
	notificationRefresh atomic.Bool
	notices             chan error
	once                sync.Once
	network             sync.Mutex
	config              syncclient.Config
	signing             ed25519.PrivateKey
	bound               *syncclient.Client
	writer              *syncclient.Writer
}

func (w *syncWorker) stop() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		w.cancel()
		<-w.done
		if w.notificationDone != nil {
			<-w.notificationDone
		}
		w.network.Lock()
		w.network.Unlock()
	})
}
func (w *syncWorker) closeWriter() { w.network.Lock(); defer w.network.Unlock(); w.writer.Close() }
func (w *syncWorker) cancelWrites(epoch uint64) error {
	w.network.Lock()
	defer w.network.Unlock()
	return w.writer.CancelPending(epoch)
}
func (w *syncWorker) report(err error) {
	if err == nil {
		return
	}
	// 关键失权事件替换队列中的普通通知，不能因旧成功提示满队列被丢弃。
	select {
	case w.notices <- err:
		return
	default:
	}
	select {
	case <-w.notices:
	default:
	}
	select {
	case w.notices <- err:
	case <-w.ctx.Done():
	}
}

// network锁同时保护定时拉取、显式共享写、绑定会话及Writer/Verifier关闭。
func (w *syncWorker) execute(ctx context.Context, operation func(context.Context, *syncclient.Client) error) error {
	w.network.Lock()
	defer w.network.Unlock()
	if w.ctx.Err() != nil {
		return localstate.ErrLocalSession
	}
	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(w.ctx, cancel)
	defer stop()
	boot := func() error {
		c, err := syncclient.NewForBoot(w.config)
		if err != nil {
			return err
		}
		w.bound, err = c.BootDevice(operationCtx, w.signing)
		return err
	}
	if w.bound == nil {
		if err := boot(); err != nil {
			return err
		}
	}
	err := operation(operationCtx, w.bound)
	var fault *syncclient.RequestError
	if errors.As(err, &fault) && fault.Status == 401 && fault.Code == "unauthorized" {
		w.bound = nil
		if err = boot(); err == nil {
			err = operation(operationCtx, w.bound)
		}
	}
	if errors.Is(err, syncclient.ErrTrustInvalidated) || errors.Is(err, localstate.ErrLocalSession) {
		w.bound = nil
	}
	return err
}
func (w *syncWorker) write(ctx context.Context, request localipc.SharedWriteRequest) (localipc.SharedWriteResult, error) {
	operation := request.Command
	if operation == "write-retry" {
		operation = "retry"
	}
	input := syncclient.WriteRequest{ID: request.RequestID, Operation: operation, EnvironmentID: request.EnvironmentID, Name: request.Name, Values: request.Selected}
	if request.Value != nil {
		input.Value = *request.Value
	}
	var result syncclient.WriteResult
	err := w.execute(ctx, func(operationCtx context.Context, client *syncclient.Client) error {
		var err error
		result, err = w.writer.Execute(operationCtx, client, input)
		return err
	})
	if errors.Is(err, syncclient.ErrTrustInvalidated) {
		w.report(err)
	}
	return localipc.SharedWriteResult{RequestID: request.RequestID, Total: result.Total, Accepted: result.Accepted, Applied: result.Applied, Sequences: result.Sequences}, err
}
func startSyncWorker(parent context.Context, engine *localstate.Engine, trust localkeys.TrustContext, signing ed25519.PrivateKey, verifier *syncclient.PinnedVerifier, vault *localkeys.Vault, r commandRuntime, interval time.Duration) (*syncWorker, error) {
	writer, err := syncclient.NewWriter(trust.AccountID, trust.AccountGeneration, trust.DeviceID, engine.State().SessionEpoch, signing, protectedWriteJournal{vault})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	worker := &syncWorker{ctx: ctx, cancel: cancel, done: make(chan struct{}), notificationDone: make(chan struct{}), wake: make(chan struct{}, 1), notices: make(chan error, 1), writer: writer, signing: signing, config: syncclient.Config{Endpoint: trust.Endpoint, HTTPClient: r.httpClient, AccountID: trust.AccountID, AccountGeneration: trust.AccountGeneration, DeviceID: trust.DeviceID, Engine: engine, Verifier: verifier, Now: r.now}}
	go func() {
		defer close(worker.done)
		for {
			if worker.notificationRefresh.Swap(false) {
				worker.network.Lock()
				worker.bound = nil
				worker.network.Unlock()
			}
			err := worker.execute(ctx, func(operationCtx context.Context, client *syncclient.Client) error {
				if engine.State().Paused {
					_, err := client.RefreshAuthorizations(operationCtx)
					if err == nil {
						err = writer.PruneUnavailable(engine.State().Cloud)
					}
					return err
				}
				_, err := client.Pull(operationCtx)
				if err == nil {
					err = writer.PruneUnavailable(engine.State().Cloud)
				}
				return err
			})
			worker.report(err)
			if errors.Is(err, syncclient.ErrPaused) {
				worker.wakeSync()
			}
			// 成功也唤醒本地收敛；通知不承载任何变量数据。
			if err == nil {
				select {
				case worker.notices <- nil:
				default:
				}
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			case <-worker.wake:
				timer.Stop()
			}
		}
	}()
	go worker.runNotifications()
	return worker, nil
}
