package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/platform"
	"github.com/harmonia-vault/core-go/syncclient"
)

type daemonOptions struct {
	directory, userID, serviceSID, ipcDirectory, fragment, windowsService string
	interval, syncInterval                                                time.Duration
	once                                                                  bool
}

// verifiedStoredContext 核验受保护的双签收据及精确公钥。证书期限是历史配对
// 挑战期限，不当成当前授权；当前环境权限仍由每次服务器检查和签授权决定。
func verifiedStoredContext(trust localkeys.TrustContext, keys localkeys.DeviceKeys, stored ...localstate.CloudSnapshot) (*syncclient.PinnedVerifier, error) {
	v, e := verifiedStoredContextReceipt(trust, keys)
	if e != nil {
		return nil, e
	}
	for _, snapshot := range stored {
		if e = v.ValidateStoredIssuerEvidence(snapshot); e != nil {
			v.Close()
			return nil, e
		}
	}
	return v, nil
}
func verifiedStoredContextReceipt(trust localkeys.TrustContext, keys localkeys.DeviceKeys) (*syncclient.PinnedVerifier, error) {
	if !trust.Accepted {
		return nil, errors.New("待完成入网不能启动网络同步")
	}
	if trust.CertificateVersion == "5" {
		receipt, e := syncclient.DecodeEnrollmentReceiptV5(trust.EnrollmentCertificate)
		if e != nil {
			return nil, e
		}
		if receipt.IdempotencyKey != trust.EnrollmentKey || receipt.Approval.PairingProfile != trust.PairingProfile || !bytes.Equal(trust.SigningPublic, keys.SigningPublic) || !bytes.Equal(trust.ReceivingPublic, keys.ReceivingPublic) || trust.DeviceID != keys.DeviceID {
			return nil, errors.New("配对资料与此设备不符，请重新配对")
		}
		return syncclient.NewPinnedVerifierV5(syncclient.IssuerDAGPinnedTrust{AccountID: trust.AccountID, AccountGeneration: trust.AccountGeneration, DeviceID: keys.DeviceID, DeviceSigningPublicKey: keys.SigningPublic, ReceivingPrivateKey: keys.ReceivingPrivate, Receipt: receipt})
	}
	return nil, errors.New("配对资料无法使用，请重新配对")
}

func fmtUint(value uint64) string { return strconv.FormatUint(value, 10) }
func wipeAccountSlots(vault *localkeys.Vault) error {
	return errors.Join(vault.Delete("device-v1"), vault.Delete("session-v1"), vault.Delete("trust-v1"), vault.Delete("writes-v1"), vault.Delete("recovery-dag-v1"))
}

func protectedDaemon(ctx context.Context, o daemonOptions, r commandRuntime, out, errOut io.Writer) error {
	if runtime.GOOS == "windows" {
		return errors.New("Windows受保护daemon的DPAPI、专用服务SID与SCM原生验收尚未通过；保持关闭")
	}
	if o.once {
		return errors.New("--once 仅用于隔离fixture收敛；受保护daemon须持续运行以处理授权与到期")
	}
	if o.windowsService != "" {
		return errors.New("当前平台不接受Windows SCM服务参数")
	}
	if o.interval < 10*time.Millisecond || o.syncInterval < time.Second {
		return errors.New("daemon interval至少10ms，sync-interval至少1s")
	}
	store, err := protectedStore(protectedOptions{directory: o.directory, userID: o.userID, serviceSID: o.serviceSID})
	if err != nil {
		return err
	}
	defer store.Close()
	engine, err := localstate.New(store)
	if err != nil {
		return err
	}
	vault := store.Vault()
	fragment := o.fragment
	if fragment == "" {
		fragment = filepath.Join(vault.Directory(), "environment.sh")
	}
	provider, err := platform.NewSecurePOSIXProvider(fragment, vault)
	if err != nil {
		return err
	}
	providerInterface := localstate.Provider(provider)
	if r.provider != nil {
		providerInterface = r.provider
	}
	directory := o.ipcDirectory
	if directory == "" {
		directory = filepath.Join(vault.Directory(), "ipc")
	}
	endpoint, err := ipcEndpoint(directory, o.userID, o.serviceSID)
	if err != nil {
		return err
	}
	daemonCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var worker *syncWorker
	var keys localkeys.DeviceKeys
	var signing ed25519.PrivateKey
	var verifier *syncclient.PinnedVerifier
	clearMaterial := func() {
		if worker != nil {
			worker.closeWriter()
		}
		if verifier != nil {
			verifier.Close()
		}
		clear(signing)
		clear(keys.SigningSeed)
		clear(keys.ReceivingPrivate)
	}
	defer func() { worker.stop(); clearMaterial() }()
	var trust localkeys.TrustContext
	var trustErr error
	if engine.State().AccountClosed {
		// 崩溃可能发生在durable logout之后、slot清理之前；绝不复活旧信任。
		if err = wipeAccountSlots(vault); err != nil {
			return err
		}
		trustErr = os.ErrNotExist
	} else {
		trust, trustErr = vault.LoadTrustContext()
	}
	if trustErr == nil && trust.Accepted {
		keys, err = vault.LoadDeviceKeys()
		if err != nil {
			return err
		}
		verifier, err = verifiedStoredContext(trust, keys, engine.State().Cloud)
		if err != nil {
			return err
		}
		signing = ed25519.NewKeyFromSeed(keys.SigningSeed)
		worker, err = startSyncWorker(daemonCtx, engine, trust, signing, verifier, vault, r, o.syncInterval)
		if err != nil {
			return err
		}
	} else if trustErr != nil && !errors.Is(trustErr, os.ErrNotExist) {
		return trustErr
	}
	server, err := localipc.Listen(localipc.Config{Endpoint: endpoint, Engine: engine, Provider: providerInterface, OnlineWrite: func(ctx context.Context, request localipc.SharedWriteRequest) (localipc.SharedWriteResult, error) {
		if worker == nil {
			return localipc.SharedWriteResult{RequestID: request.RequestID}, syncclient.ErrWritePermission
		}
		return worker.write(ctx, request)
	}, OnLogout: func(context.Context) error {
		// worker 不获取 IPC operations 锁；取消后等待所有HTTP/验签，避免回调死锁。
		worker.stop()
		clearMaterial()
		return wipeAccountSlots(vault)
	}})
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(daemonCtx) }()
	defer func() { cancel(); _ = server.Close(); <-done }()
	if err = server.Reconcile(daemonCtx, time.Now()); err != nil {
		return daemonLoopError(daemonCtx, err)
	}
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	var notices <-chan error
	if worker != nil {
		notices = worker.notices
	}
	for {
		select {
		case <-daemonCtx.Done():
			return nil
		case err := <-done:
			done <- err
			return daemonLoopError(daemonCtx, err)
		case now := <-ticker.C:
			if err = server.Reconcile(daemonCtx, now); err != nil {
				return daemonLoopError(daemonCtx, err)
			}
		case syncErr := <-notices:
			if errors.Is(syncErr, syncclient.ErrTrustInvalidated) {
				var rejected *syncclient.RequestError
				if errors.As(syncErr, &rejected) && rejected.Code == "no_current_grant" {
					if err = worker.cancelWrites(engine.State().SessionEpoch); err != nil {
						return err
					}
					if err = vault.Delete("session-v1"); err != nil {
						return err
					}
				} else {
					worker.stop()
					clearMaterial()
					notices = nil
					if err = wipeAccountSlots(vault); err != nil {
						return err
					}
				}
			}
			// 普通网络错误保持离线配置；本地期限独立由ticker检查，不日志值/请求。
			if err = server.Reconcile(daemonCtx, time.Now()); err != nil {
				return daemonLoopError(daemonCtx, err)
			}
		}
	}
}

// select可能在取消到达前选中ticker/通知；provider随后返回精确的context.Canceled。
// 仅这一正常结束结果归零，不能因上下文同时取消吞掉真实持久化/provider错误。
func daemonLoopError(ctx context.Context, err error) error {
	if ctx.Err() != nil && err == context.Canceled {
		return nil
	}
	return err
}
