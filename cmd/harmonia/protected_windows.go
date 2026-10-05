//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/platform"
	"github.com/harmonia-vault/core-go/syncclient"
	"github.com/harmonia-vault/core-go/windowsservice"
	"golang.org/x/sys/windows"
)

func ownWindowsSyncIdentity(c windowsservice.Config, userSID string) bool {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || user.User.Sid.String() != userSID {
		return false
	}
	var image [32768]uint16
	size := uint32(len(image))
	return windows.QueryFullProcessImageName(windows.CurrentProcess(), 0, &image[0], &size) == nil && strings.EqualFold(windows.UTF16ToString(image[:size]), c.SyncExecutable)
}
func windowsEndpointFromConfig(c windowsservice.Config) localipc.Endpoint {
	return localipc.Endpoint{Directory: filepath.Join(filepath.Dir(c.ConfigurationFile), "vault-"+c.Tag(), "ipc"), UserID: c.TargetSID, ServiceSID: c.SyncServiceSID, WindowsConfigFile: c.ConfigurationFile}
}
func windowsClientEndpoint(configFile string) (localipc.Endpoint, error) {
	locked, e := windowsservice.LoadConfig(configFile)
	if e != nil {
		return localipc.Endpoint{}, e
	}
	defer locked.Close()
	if !ownWindowsSyncIdentity(locked.Config, locked.Config.TargetSID) {
		return localipc.Endpoint{}, localipc.ErrIdentity
	}
	return windowsEndpointFromConfig(locked.Config), nil
}
func protectedWindowsAccount(ctx context.Context, configFile string, o protectedOptions, pairingID string, r commandRuntime, out, errOut io.Writer) error {
	endpoint, e := windowsClientEndpoint(configFile)
	if e != nil {
		return e
	}
	request := localipc.AccountRequest{Action: o.command}
	switch o.command {
	case "login":
		password, e := readLoginPassword(r.input, o.passwordStdin, errOut)
		if e != nil {
			return e
		}
		defer clear(password)
		hash := cryptox.PasswordCredential(string(password))
		defer clear(hash[:])
		request.Endpoint = o.server
		request.Email = o.email
		request.Credential = hash[:]
	case "pair":
		request.ApproverDeviceID = o.approver
		request.CertificateVersion = "5"
	case "pair-status", "pair-cancel":
		request.PairingID = pairingID
	default:
		return localipc.ErrProtocol
	}
	response, e := localipc.Call(ctx, endpoint, localipc.Request{Command: "account", Account: &request})
	if e != nil {
		return e
	}
	if !response.OK {
		return fmt.Errorf("后台账号操作失败：%s", response.Code)
	}
	if response.Account == nil {
		return localipc.ErrProtocol
	}
	state := response.Account
	switch state.Phase {
	case "logged-in":
		_, e = io.WriteString(out, "登录会话已由专用系统服务加密保存；设备尚未可信。\n")
	case "pairing":
		_, e = fmt.Fprintf(out, "配对申请：%s\n请在管理手机输入本机短码：%s\n关闭CLI后服务继续处理；用pair-status查询原申请。\n", state.PairingID, state.ShortCode)
	case "pending":
		_, e = fmt.Fprintf(out, "原配对申请%s结果待确认；只能查询或恢复原收据。\n", state.PairingID)
	case "accepted":
		_, e = fmt.Fprintf(out, "原配对申请%s已接受；下发完成：%t。\n", state.PairingID, state.Applied)
	case "cancelled":
		_, e = io.WriteString(out, "尚未密封的配对申请已取消。\n")
	case "failed":
		return errors.New("原配对任务未完成；未开放设备信任")
	default:
		return localipc.ErrProtocol
	}
	return e
}

// Windows sync服务独占材料；SYSTEM broker只经ProfileClient操作固定用户注册表。
type windowsSyncOwner struct {
	ctx                context.Context
	store              *localkeys.StateStore
	engine             *localstate.Engine
	runtime            commandRuntime
	interval           time.Duration
	mu                 sync.RWMutex
	worker             *syncWorker
	keys               localkeys.DeviceKeys
	signing            ed25519.PrivateKey
	verifier           *syncclient.PinnedVerifier
	changed            chan struct{}
	reconciledEpoch    uint64
	reconciledSequence uint64
}

func (o *windowsSyncOwner) signal() {
	select {
	case o.changed <- struct{}{}:
	default:
	}
}
func (o *windowsSyncOwner) startSync() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ctx.Err() != nil || o.engine.State().AccountClosed {
		return localstate.ErrLocalSession
	}
	if o.worker != nil {
		return nil
	}
	trust, e := o.store.Vault().LoadTrustContext()
	if e != nil {
		return e
	}
	keys, e := o.store.Vault().LoadDeviceKeys()
	if e != nil {
		return e
	}
	verifier, e := verifiedStoredContext(trust, keys, o.engine.State().Cloud)
	if e != nil {
		clear(keys.SigningSeed)
		clear(keys.ReceivingPrivate)
		return e
	}
	signing := ed25519.NewKeyFromSeed(keys.SigningSeed)
	worker, e := startSyncWorker(o.ctx, o.engine, trust, signing, verifier, o.store.Vault(), o.runtime, o.interval)
	if e != nil {
		verifier.Close()
		clear(signing)
		clear(keys.SigningSeed)
		clear(keys.ReceivingPrivate)
		return e
	}
	o.keys = keys
	o.signing = signing
	o.verifier = verifier
	o.worker = worker
	o.signal()
	return nil
}
func (o *windowsSyncOwner) stopSync() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.worker != nil {
		o.worker.stop()
		o.worker.closeWriter()
		o.worker = nil
	}
	if o.verifier != nil {
		o.verifier.Close()
		o.verifier = nil
	}
	clear(o.keys.SigningSeed)
	clear(o.keys.ReceivingPrivate)
	clear(o.signing)
	o.keys = localkeys.DeviceKeys{}
	o.signing = nil
	o.reconciledSequence = 0
	o.reconciledEpoch = 0
	o.signal()
}
func (o *windowsSyncOwner) write(ctx context.Context, r localipc.SharedWriteRequest) (localipc.SharedWriteResult, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.worker == nil {
		return localipc.SharedWriteResult{RequestID: r.RequestID}, syncclient.ErrWritePermission
	}
	return o.worker.write(ctx, r)
}
func (o *windowsSyncOwner) notices() <-chan error {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.worker == nil {
		return nil
	}
	return o.worker.notices
}
func (o *windowsSyncOwner) currentNotices(ch <-chan error) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.worker != nil && ch == o.worker.notices
}
func (o *windowsSyncOwner) markReconciled() {
	state := o.engine.State()
	o.mu.Lock()
	o.reconciledSequence = state.Cloud.Sequence
	o.reconciledEpoch = state.SessionEpoch
	o.mu.Unlock()
}
func (o *windowsSyncOwner) inspect() (localipc.AccountState, error) {
	state := o.engine.State()
	if state.AccountClosed {
		return localipc.AccountState{Phase: "idle"}, nil
	}
	trust, e := o.store.Vault().LoadTrustContext()
	if errors.Is(e, os.ErrNotExist) {
		if _, e = o.store.Vault().LoadSession(); e == nil {
			return localipc.AccountState{Phase: "logged-in"}, nil
		}
		if errors.Is(e, os.ErrNotExist) {
			return localipc.AccountState{Phase: "idle"}, nil
		}
		return localipc.AccountState{}, e
	}
	if e != nil {
		return localipc.AccountState{}, e
	}
	out := localipc.AccountState{Phase: "pending", PairingID: trust.EnrollmentKey}
	if trust.Accepted {
		out.Phase = "accepted"
		out.Accepted = true
		o.mu.RLock()
		out.Applied = state.Cloud.AccountID == trust.AccountID && state.Cloud.AccountGeneration == trust.AccountGeneration && state.Cloud.Sequence > 0 && o.reconciledEpoch == state.SessionEpoch && o.reconciledSequence >= state.Cloud.Sequence
		o.mu.RUnlock()
	}
	return out, nil
}
func protectedWindowsDaemon(ctx context.Context, configFile string, o daemonOptions, r commandRuntime, out, errOut io.Writer) (result error) {
	locked, e := windowsservice.LoadConfig(configFile)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, locked.Close()) }()
	c := locked.Config
	if o.windowsService != c.SyncServiceName() || !ownWindowsSyncIdentity(c, c.SyncServiceSID) {
		return localipc.ErrIdentity
	}
	if o.once || o.interval < 10*time.Millisecond || o.syncInterval < time.Second {
		return errors.New("Windows daemon须持续运行，interval至少10ms、sync-interval至少1s")
	}
	return runWindowsOwnerService(ctx, c.SyncServiceName(), func(serviceCtx context.Context, ready func()) error {
		return runWindowsProtectedOwner(serviceCtx, c, o, r, ready)
	})
}
func runWindowsProtectedOwner(ctx context.Context, c windowsservice.Config, o daemonOptions, r commandRuntime, ready func()) (result error) {
	directory := filepath.Join(filepath.Dir(c.ConfigurationFile), "vault-"+c.Tag())
	store, e := localkeys.OpenEncryptedStateStore(localkeys.Config{Directory: directory, UserID: c.TargetSID, ServiceSID: c.SyncServiceSID})
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	engine, e := localstate.New(store)
	if e != nil {
		return e
	}
	registry, e := windowsservice.NewProfileClient(ctx, c)
	if e != nil {
		return e
	}
	provider, e := platform.NewSecureWindowsProvider(c.TargetSID, registry, store.Vault())
	if e != nil {
		return e
	}
	owner := &windowsSyncOwner{ctx: ctx, store: store, engine: engine, runtime: r, interval: o.syncInterval, changed: make(chan struct{}, 1)}
	defer owner.stopSync()
	if engine.State().AccountClosed {
		if e = wipeAccountSlots(store.Vault()); e != nil {
			return e
		}
	} else if trust, te := store.Vault().LoadTrustContext(); te == nil && trust.Accepted {
		if e = owner.startSync(); e != nil {
			return e
		}
	} else if te != nil && !errors.Is(te, os.ErrNotExist) {
		return te
	}
	base := protectedOptions{directory: directory, userID: c.TargetSID, serviceSID: c.SyncServiceSID}
	account := newAccountOwner(ctx, accountOwnerCallbacks{Epoch: func() uint64 { return engine.State().SessionEpoch }, Inspect: owner.inspect, Accepted: owner.startSync,
		Login: func(callCtx context.Context, request localipc.AccountRequest) error {
			options := base
			options.command = "login"
			options.server = request.Endpoint
			options.email = request.Email
			runtime := r
			runtime.loginCredential = request.Credential
			return protectedAccountOnOwner(callCtx, options, runtime, io.Discard, io.Discard, store, engine)
		},
		Pair: func(callCtx context.Context, request localipc.AccountRequest, epoch uint64, progress func(string, []byte)) error {
			options := base
			options.command = "pair"
			options.approver = request.ApproverDeviceID
			runtime := r
			runtime.pairingProgress = progress
			runtime.enrollmentEpoch = &epoch
			return protectedAccountOnOwner(callCtx, options, runtime, io.Discard, io.Discard, store, engine)
		},
	})
	defer account.Close()
	server, e := localipc.Listen(localipc.Config{Endpoint: windowsEndpointFromConfig(c), Engine: engine, Provider: provider, Account: account.Handle, OnlineWrite: owner.write, OnLogout: func(context.Context) error {
		account.stopPair()
		owner.stopSync()
		return wipeAccountSlots(store.Vault())
	}})
	if e != nil {
		return e
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(runCtx) }()
	defer func() { cancel(); result = errors.Join(result, server.Close()); <-done }()
	reconcile := func(now time.Time) error {
		if e := server.Reconcile(runCtx, now); e != nil {
			return daemonLoopError(runCtx, e)
		}
		owner.markReconciled()
		return nil
	}
	if e = reconcile(time.Now()); e != nil {
		return e
	}
	ready()
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	notices := owner.notices()
	for {
		select {
		case <-runCtx.Done():
			return nil
		case e := <-done:
			done <- e
			return daemonLoopError(runCtx, e)
		case <-owner.changed:
			notices = owner.notices()
		case now := <-ticker.C:
			if e = reconcile(now); e != nil {
				return e
			}
		case syncErr := <-notices:
			if !owner.currentNotices(notices) {
				continue
			}
			if errors.Is(syncErr, syncclient.ErrTrustInvalidated) {
				var rejected *syncclient.RequestError
				if errors.As(syncErr, &rejected) && rejected.Code == "no_current_grant" {
					owner.mu.RLock()
					e = owner.worker.cancelWrites(engine.State().SessionEpoch)
					owner.mu.RUnlock()
					if e != nil {
						return e
					}
					if e = store.Vault().Delete("session-v1"); e != nil {
						return e
					}
				} else {
					account.stopPair()
					owner.stopSync()
					notices = nil
					if e = wipeAccountSlots(store.Vault()); e != nil {
						return e
					}
				}
			}
			if e = reconcile(time.Now()); e != nil {
				return e
			}
		}
	}
}
