//go:build darwin || linux

package localipc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

// 这里的合成快照仅由测试进程内部构造；生产 IPC 不接受快照或信任资料。
// State.Synthetic 表示公开未签名 fixture 入口的来源，不能将该来源迁移到加密 Store。
func TestEncryptedOwnerIPCLogoutFailureAndRestart(t *testing.T) {
	endpoint := temporaryEndpoint(t)
	canonical, err := filepath.EvalSymlinks(endpoint.Directory)
	must(t, err)
	config := localkeys.Config{Directory: filepath.Join(canonical, "protected"), UserID: endpoint.UserID}
	store, err := localkeys.OpenEncryptedStateStore(config)
	must(t, err)
	engine, err := localstate.New(store)
	must(t, err)
	source, _, provider := fixture(t)
	device, err := localkeys.GenerateDeviceKeys("synthetic-device")
	must(t, err)
	must(t, store.Vault().SaveDeviceKeys(device))
	must(t, store.Vault().SaveSession(localkeys.LoginSession{
		Endpoint: "https://synthetic.invalid", AccountID: "synthetic", AccountGeneration: 1,
		Token: "synthetic-device-session-32-bytes", ExpiresAt: syntheticNow.Add(time.Hour).Format(time.RFC3339),
	}))
	// 仅存储层合成 fixture：没有绕过生产 CLI 的证书/PAKE 校验入口。
	must(t, store.Vault().SaveTrustContext(localkeys.TrustContext{Endpoint: "https://synthetic.invalid", AccountID: "synthetic", AccountGeneration: 1, DeviceID: device.DeviceID, SigningPublic: device.SigningPublic, ReceivingPublic: device.ReceivingPublic, CertificateVersion: "5", PairingProfile: localkeys.EnrollmentPairingProfile, EnrollmentCertificate: []byte(`{"syntheticStorageFixture":true}`), EnrollmentKey: "synthetic-storage-test", Accepted: true}))
	must(t, engine.AcceptSnapshot(source.State().Cloud, syntheticNow))
	if second, err := localkeys.OpenEncryptedStateStore(config); err == nil {
		_ = second.Close()
		t.Fatal("second encrypted state owner accepted")
	}
	initialEpoch := engine.State().SessionEpoch
	cleaned := false
	server, err := Listen(Config{Endpoint: endpoint, Engine: engine, Provider: provider,
		Now: func() time.Time { return syntheticNow }, OnLogout: func(context.Context) error {
			if engine.State().SessionEpoch == initialEpoch || len(engine.State().Cloud.Environments) != 0 {
				return errors.New("logout cleanup ran before session/cache invalidation")
			}
			cleaned = true
			return errors.Join(store.Vault().Delete("device-v1"), store.Vault().Delete("session-v1"), store.Vault().Delete("trust-v1"))
		}})
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	firstStore := store
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() { cancel(); must(t, <-done); must(t, server.Close()); must(t, firstStore.Close()) })
	}
	defer stop()
	response, err := Call(context.Background(), endpoint, Request{Command: "activate", EnvironmentID: "one"})
	must(t, err)
	if !response.OK {
		t.Fatal(response)
	}
	response, err = Call(context.Background(), endpoint, Request{Command: "override-set", EnvironmentID: "one", Name: "TOKEN", Value: ptr("synthetic-encrypted-local")})
	must(t, err)
	if !response.OK {
		t.Fatal(response)
	}
	entries, err := os.ReadDir(config.Directory)
	must(t, err)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(config.Directory, entry.Name()))
		must(t, err)
		for _, plaintext := range []string{"synthetic-cloud", "synthetic-encrypted-local", "synthetic-device-session-32-bytes"} {
			if bytes.Contains(content, []byte(plaintext)) {
				t.Fatal("plaintext found in encrypted owner storage")
			}
		}
	}
	// 恢复失败时缓存与设备/session 仍应被清除，原值名字则持续保存以便重试。
	provider.failed = true
	response, err = Call(context.Background(), endpoint, Request{Command: "logout"})
	must(t, err)
	if response.OK || response.Code != "provider_or_persistence_failed" || !cleaned {
		t.Fatal(response)
	}
	if len(engine.State().Cloud.Environments) != 0 || len(engine.State().Managed) != 0 || engine.State().Originals["TOKEN"].Value != "original" {
		t.Fatal("logout did not separate erased cache from pending restoration")
	}
	for _, slot := range []string{"device-v1", "session-v1", "trust-v1"} {
		if _, err := store.Vault().Load(slot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("logout retained credentials", slot, err)
		}
	}
	stop()
	store, err = localkeys.OpenEncryptedStateStore(config)
	must(t, err)
	defer store.Close()
	engine, err = localstate.New(store)
	must(t, err)
	if engine.State().SessionEpoch != initialEpoch+1 || len(engine.State().Cloud.Environments) != 0 {
		t.Fatal("session invalidation was not durable")
	}
	provider.failed = false
	restarted, restartCancel, restartDone := startServer(t, endpoint, engine, provider)
	defer func() { restartCancel(); must(t, <-restartDone); must(t, restarted.Close()) }()
	must(t, restarted.Reconcile(context.Background(), syntheticNow))
	response, err = Call(context.Background(), endpoint, Request{Command: "status"})
	must(t, err)
	if !response.OK || response.Status.TrackedOriginals != 0 || provider.values["TOKEN"] != "original" || provider.values["UNRELATED"] != "keep" {
		t.Fatal(response)
	}
	if _, exists := provider.values["ADDED"]; exists {
		t.Fatal("restart retained a tool-added variable")
	}
}
