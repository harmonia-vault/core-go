//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/platform"
)

type noImportEnvironment struct{}

func (noImportEnvironment) Names() []string              { panic("不应枚举宿主env") }
func (noImportEnvironment) Lookup(string) (string, bool) { panic("不应读取宿主env") }
func (noImportEnvironment) CaseInsensitive() bool        { panic("不应扫描宿主env") }

type zeroHTTPTransport struct{ calls atomic.Int32 }

func (t *zeroHTTPTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("离线命令不应访问HTTP")
}
func offlineSeed(t *testing.T) (string, string, []byte) {
	t.Helper()
	directory := protectedTestDirectory(t)
	uid, e := localkeys.CurrentUserID()
	mustCLI(t, e)
	store, e := protectedStore(protectedOptions{directory: directory, userID: uid})
	mustCLI(t, e)
	defer store.Close()
	v := store.Vault()
	keys, e := localkeys.GenerateDeviceKeys("synthetic-offline-device")
	mustCLI(t, e)
	defer clear(keys.SigningSeed)
	defer clear(keys.ReceivingPrivate)
	mustCLI(t, v.SaveDeviceKeys(keys))
	// 只作已加密本地存储清理测试，不拿合成收据当真实信任/密码学通过。
	mustCLI(t, v.SaveTrustContext(localkeys.TrustContext{Endpoint: "https://synthetic.invalid", AccountID: "synthetic-account", AccountGeneration: 1, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, CertificateVersion: "5", PairingProfile: pairing.Profile, EnrollmentCertificate: []byte(`{"syntheticStorageOnly":true}`), EnrollmentKey: "synthetic-old-enrollment", Accepted: true}))
	mustCLI(t, v.SaveSession(localkeys.LoginSession{Endpoint: "https://synthetic.invalid", AccountID: "synthetic-account", AccountGeneration: 1, Token: "synthetic-login-only", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}))
	mustCLI(t, v.Save("writes-v1", []byte(`{"syntheticPendingOnly":true}`)))
	mustCLI(t, v.Save("recovery-dag-v1", []byte(`{"syntheticJournalOnly":true}`)))
	engine, e := localstate.New(store)
	mustCLI(t, e)
	now := time.Now()
	mustCLI(t, engine.AcceptSnapshot(localstate.CloudSnapshot{AccountID: "synthetic-account", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{"e": {ID: "e", KeyVersion: 1, GrantGeneration: 1, Role: localstate.ReadWrite, Values: map[string]string{"VX": "synthetic-cloud-only", "NEW_KEY": "synthetic-added-only"}}}}, now))
	mustCLI(t, engine.Activate("e", 1, now))
	mustCLI(t, engine.SetOverride("e", "VX", "synthetic-local-override", now))
	provider, e := platform.NewSecurePOSIXProvider(filepath.Join(directory, "environment.sh"), v)
	mustCLI(t, e)
	mustCLI(t, engine.Reconcile(context.Background(), provider, now))
	mustCLI(t, engine.SetPaused(true))
	mustCLI(t, engine.Reconcile(context.Background(), provider, now))
	b, e := os.ReadFile(filepath.Join(directory, "environment.sh"))
	mustCLI(t, e)
	return directory, uid, b
}
func runOffline(t *testing.T, directory, uid string) (string, error, *zeroHTTPTransport) {
	t.Helper()
	tr := &zeroHTTPTransport{}
	var out, errOut bytes.Buffer
	e := runWithRuntime(context.Background(), []string{"logout", "--offline-local", "--local-directory", directory, "--local-user", uid}, &out, &errOut, commandRuntime{httpClient: &http.Client{Transport: tr}, environment: noImportEnvironment{}})
	return out.String(), e, tr
}
func requireOfflineClosed(t *testing.T, directory, uid string, epoch uint64) {
	t.Helper()
	s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	defer s.Close()
	state, e := s.Load()
	mustCLI(t, e)
	if !state.AccountClosed || state.SessionEpoch != epoch || len(state.Originals) != 0 || len(state.Managed) != 0 || len(state.Overrides) != 0 || len(state.Active) != 0 || len(state.Cloud.Environments) != 0 || state.Cloud.AccountID != "" {
		t.Fatal("持久退出/恢复未完成")
	}
	for _, slot := range []string{"device-v1", "session-v1", "trust-v1", "writes-v1", "recovery-dag-v1"} {
		if _, e = s.Vault().Load(slot); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("账号材料尚存", slot, e)
		}
	}
}
func TestOfflineLogoutRealEncryptedStateAndSameShellRestoreWithoutHTTPOrDaemon(t *testing.T) {
	directory, uid, _ := offlineSeed(t)
	quoted, e := platform.ShellQuote(filepath.Join(directory, "environment.sh"))
	mustCLI(t, e)
	// 同一个真实 sh 先消费云片段，退出后再次消费 release，逐 key 恢复自己的原值。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "VX=synthetic-shell-original; export VX UNRELATED=synthetic-unrelated; unset NEW_KEY; . "+quoted+"; printf '%s\\n' \"$VX\"; IFS= read -r go; . "+quoted+"; printf '%s|%s|%s\\n' \"$VX\" \"$UNRELATED\" \"${NEW_KEY+x}\"")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdout, e := cmd.StdoutPipe()
	mustCLI(t, e)
	stdin, e := cmd.StdinPipe()
	mustCLI(t, e)
	mustCLI(t, cmd.Start())
	defer func() {
		stdin.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	rd := bufio.NewReader(stdout)
	line, e := rd.ReadString('\n')
	mustCLI(t, e)
	if line != "synthetic-local-override\n" {
		t.Fatal("未接管合成值")
	}
	out, e, tr := runOffline(t, directory, uid)
	mustCLI(t, e)
	if out != "{\"version\":1,\"localLogoutComplete\":true}\n" || tr.calls.Load() != 0 {
		t.Fatal("完成DTO或HTTP边界不符")
	}
	if _, e = os.Lstat(filepath.Join(directory, "ipc")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("离线命令建立了IPC/daemon", e)
	}
	_, e = io.WriteString(stdin, "continue\n")
	mustCLI(t, e)
	stdin.Close()
	line, e = rd.ReadString('\n')
	mustCLI(t, e)
	if line != "synthetic-shell-original|synthetic-unrelated|\n" {
		t.Fatal("同shell逐key恢复或无关变量保护失败")
	}
	mustCLI(t, cmd.Wait())
	requireOfflineClosed(t, directory, uid, 1)
	_, e, tr = runOffline(t, directory, uid)
	mustCLI(t, e)
	if tr.calls.Load() != 0 {
		t.Fatal("重试联网")
	}
	requireOfflineClosed(t, directory, uid, 1)
}
func TestOfflineLogoutRejectsParametersBeforeOpeningOrNetwork(t *testing.T) {
	uid, e := localkeys.CurrentUserID()
	mustCLI(t, e)
	for _, args := range [][]string{
		{"login", "--offline-local"}, {"logout", "--offline-local"}, {"logout", "--offline-local", "--local-directory", "relative", "--local-user", uid}, {"logout", "--offline-local", "--local-directory", "/", "--local-user", uid},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", "0"},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", uid, "--fixture"},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", uid, "--ca-file", "/private-user-file"},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", uid, "--server", "https://synthetic.invalid"},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", uid, "--platform-fragment", "/unrelated"},
		{"logout", "--offline-local", "--local-directory", "/synthetic-absent", "--local-user", uid, "extra"},
	} {
		t.Run(strings.Join(args[:2], "-")+strings.Join(args[2:], "-"), func(t *testing.T) {
			tr := &zeroHTTPTransport{}
			var out bytes.Buffer
			if e := runWithRuntime(context.Background(), args, &out, io.Discard, commandRuntime{httpClient: &http.Client{Transport: tr}}); e == nil {
				t.Fatal("非法offline参数通过")
			}
			if out.Len() != 0 || tr.calls.Load() != 0 {
				t.Fatal("拒绝前发生输出/HTTP")
			}
		})
	}
}
func TestOfflineLogoutOwnerBusyPreservesAccount(t *testing.T) {
	directory, uid, _ := offlineSeed(t)
	store, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	defer store.Close()
	out, e, tr := runOffline(t, directory, uid)
	if !errors.Is(e, localkeys.ErrBusy) || out != "" || tr.calls.Load() != 0 {
		t.Fatal("没有排除真实owner", e)
	}
	state, e := store.Load()
	mustCLI(t, e)
	if state.AccountClosed || state.Cloud.AccountID == "" {
		t.Fatal("锁忙仍清理账号")
	}
}
func TestOfflineLogoutProviderFailurePersistsClosedAndRetriesWithoutNewEpoch(t *testing.T) {
	directory, uid, goodFragment := offlineSeed(t)
	fragment := filepath.Join(directory, "environment.sh")
	// 模拟未知文件替换；正式 provider 不能覆盖，恢复失败不能报完成。
	mustCLI(t, os.WriteFile(fragment, []byte("synthetic-unrelated-file\n"), 0600))
	out, e, tr := runOffline(t, directory, uid)
	if e == nil || out != "" || tr.calls.Load() != 0 {
		t.Fatal("provider失败假成功", e)
	}
	s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	state, e := s.Load()
	mustCLI(t, e)
	if !state.AccountClosed || state.SessionEpoch != 1 || len(state.Originals) != 2 {
		t.Fatal("失败没有保留恢复记录")
	}
	mustCLI(t, s.Close())
	mustCLI(t, os.WriteFile(fragment, goodFragment, 0600))
	_, e, _ = runOffline(t, directory, uid)
	mustCLI(t, e)
	requireOfflineClosed(t, directory, uid, 1)
}

type failFinalStore struct {
	store *localkeys.StateStore
	calls int
}

func (s *failFinalStore) Load() (localstate.State, error) { return s.store.Load() }
func (s *failFinalStore) Save(state localstate.State) error {
	s.calls++
	if s.calls == 2 {
		return errors.New("合成最终Save失败")
	}
	return s.store.Save(state)
}
func TestOfflineLogoutFinalSaveFailureKeepsRestorationForRetry(t *testing.T) {
	directory, uid, _ := offlineSeed(t)
	s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	engine, e := localstate.New(s)
	mustCLI(t, e)
	mustCLI(t, engine.Logout())
	mustCLI(t, wipeAccountSlots(s.Vault()))
	failing := &failFinalStore{store: s}
	engine, e = localstate.New(failing)
	mustCLI(t, e)
	provider, e := platform.NewSecurePOSIXLogoutProvider(filepath.Join(directory, "environment.sh"), s.Vault())
	mustCLI(t, e)
	if e = completeLocalRestoration(context.Background(), engine, provider, time.Now()); e == nil {
		t.Fatal("最终Save失败假报完成")
	}
	state, e := s.Load()
	mustCLI(t, e)
	if !state.AccountClosed || len(state.Originals) != 2 {
		t.Fatal("最终Save失败丢恢复记录")
	}
	mustCLI(t, s.Close())
	_, e, tr := runOffline(t, directory, uid)
	mustCLI(t, e)
	if tr.calls.Load() != 0 {
		t.Fatal("修复重试联网")
	}
	requireOfflineClosed(t, directory, uid, 1)
}

func TestOfflineLogoutActualIdleDaemonOwnerRejectsBeforeCleanup(t *testing.T) {
	directory := protectedTestDirectory(t)
	uid, e := localkeys.CurrentUserID()
	mustCLI(t, e)
	s, e := protectedStore(protectedOptions{directory: directory, userID: uid})
	mustCLI(t, e)
	mustCLI(t, s.Close())
	tr := &zeroHTTPTransport{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--local-user", uid, "--interval", "20ms", "--sync-interval", "1s"}, io.Discard, io.Discard, commandRuntime{httpClient: &http.Client{Transport: tr}})
	}()
	defer func() { cancel(); mustCLI(t, <-done) }()
	ep, e := ipcEndpoint(filepath.Join(directory, "ipc"), uid, "")
	mustCLI(t, e)
	eventuallyCLI(t, func() bool {
		response, e := localipc.Call(context.Background(), ep, localipc.Request{Command: "status"})
		return e == nil && response.OK
	})
	out, e, offlineTransport := runOffline(t, directory, uid)
	if !errors.Is(e, localkeys.ErrBusy) || out != "" || tr.calls.Load() != 0 || offlineTransport.calls.Load() != 0 {
		t.Fatal("运行中正式owner没有拒离线清理", e)
	}
	response, e := localipc.Call(context.Background(), ep, localipc.Request{Command: "status"})
	mustCLI(t, e)
	if !response.OK {
		t.Fatal("离线拒绝破坏运行owner")
	}
}
func TestOfflineLogoutClosedMaxEpochStillCompletesRemainingCleanup(t *testing.T) {
	directory, uid, _ := offlineSeed(t)
	s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	engine, e := localstate.New(s)
	mustCLI(t, e)
	mustCLI(t, engine.Logout())
	state := engine.State()
	state.SessionEpoch = ^uint64(0)
	mustCLI(t, s.Save(state))
	mustCLI(t, s.Close())
	_, e, tr := runOffline(t, directory, uid)
	mustCLI(t, e)
	if tr.calls.Load() != 0 {
		t.Fatal("关闭重试联网")
	}
	requireOfflineClosed(t, directory, uid, ^uint64(0))
}
func TestOfflineLogoutUntrackedEncryptedProviderDoesNotWriteOrClaimSuccess(t *testing.T) {
	directory, uid, _ := offlineSeed(t)
	s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	p, e := platform.NewSecurePOSIXProvider(filepath.Join(directory, "environment.sh"), s.Vault())
	mustCLI(t, e)
	extra := "synthetic-untracked-value"
	mustCLI(t, p.Apply(context.Background(), []localstate.Change{{Name: "UNTRACKED", Value: &extra}}))
	mustCLI(t, s.Close())
	before, e := os.ReadFile(filepath.Join(directory, "environment.sh"))
	mustCLI(t, e)
	out, e, tr := runOffline(t, directory, uid)
	if e == nil || out != "" || tr.calls.Load() != 0 {
		t.Fatal("未对应接管记录的Desired假成功", e)
	}
	after, e := os.ReadFile(filepath.Join(directory, "environment.sh"))
	mustCLI(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("拒绝前写入了fragment")
	}
}
