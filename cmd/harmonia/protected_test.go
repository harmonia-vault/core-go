//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

func mustCLI(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func protectedTestDirectory(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("受保护IPC仅用普通临时用户")
	}
	parent, err := os.MkdirTemp("/tmp", "harmonia-sec-")
	mustCLI(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	parent, err = filepath.EvalSymlinks(parent)
	mustCLI(t, err)
	return filepath.Join(parent, "vault")
}
func TestProtectedLoginPersistsOnlyEncryptedRandomSession(t *testing.T) {
	directory := protectedTestDirectory(t)
	password := "SYNTHETIC-password-only-for-test"
	hash := cryptox.PasswordCredential(password)
	token := cryptox.EncodeBase64(append([]byte{5}, make([]byte, 31)...))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		if r.URL.Path != "/v1/login" || r.Header.Get("Authorization") != "" {
			t.Error("login sent device identity/credential in wrong channel")
		}
		var request struct {
			Email      string `json:"email"`
			Credential string `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Email != "synthetic@example.invalid" || request.Credential != strings.ToLower(fmtHex(hash[:])) {
			t.Error("password credential was not exact SHA256")
		}
		_ = json.NewEncoder(w).Encode(syncclient.LoginResult{AccountID: "acct", AccountGeneration: "1", Token: token, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	var output bytes.Buffer
	mustCLI(t, runWithRuntime(context.Background(), []string{"login", "--local-directory", directory, "--server", server.URL, "--email", "synthetic@example.invalid", "--password-stdin"}, &output, io.Discard, commandRuntime{input: strings.NewReader(password + "\n"), httpClient: server.Client()}))
	if strings.Contains(output.String(), password) || strings.Contains(output.String(), token) || strings.Contains(output.String(), fmtHex(hash[:])) {
		t.Fatal("login output leaked secret")
	}
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	session, err := store.Vault().LoadSession()
	mustCLI(t, err)
	if session.Token != token {
		t.Fatal("session missing")
	}
	if _, err = store.Vault().LoadTrustContext(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("password login created trust", err)
	}
	mustCLI(t, store.Close())
	_ = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && !entry.IsDir() {
			data, err := os.ReadFile(path)
			mustCLI(t, err)
			for _, secret := range []string{password, token, fmtHex(hash[:])} {
				if bytes.Contains(data, []byte(secret)) {
					t.Error("secret appeared in persisted plaintext", entry.Name())
				}
			}
		}
		return walkErr
	})
	if _, err = commandTest(t, "login", "--local-directory", directory, "--fixture"); err == nil {
		t.Fatal("fixture mixed with protected state")
	}
}
func fmtHex(data []byte) string {
	const alphabet = "0123456789abcdef"
	var result strings.Builder
	for _, b := range data {
		result.WriteByte(alphabet[b>>4])
		result.WriteByte(alphabet[b&15])
	}
	return result.String()
}
func TestDefaultPairCannotCreateProtectedFilesOrSendRequests(t *testing.T) {
	if pairing.NativeAvailable() {
		t.Skip("默认构建关闭测试；原生配对由tagged集成验收")
	}
	directory := protectedTestDirectory(t)
	if err := runWithRuntime(context.Background(), []string{"pair", "--local-directory", directory, "--approver", "manager"}, io.Discard, io.Discard, commandRuntime{}); !errors.Is(err, pairing.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unavailable primitive created state")
	}
}

type isolatedProvider struct {
	mu     sync.Mutex
	values map[string]string
}

func (p *isolatedProvider) Snapshot(_ context.Context, keys []string) (map[string]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := p.values[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}
func (p *isolatedProvider) Apply(_ context.Context, changes []localstate.Change) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range changes {
		if c.Value == nil {
			delete(p.values, c.Name)
		} else {
			p.values[c.Name] = *c.Value
		}
	}
	return nil
}
func (p *isolatedProvider) value(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.values[name]
}
func eventuallyCLI(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("后台状态未在期限内收敛")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// 合成签证只测试正式daemon编排；真实SPAKE2确认另由tagged与workspace端到端测试覆盖。
func TestProtectedDaemonBootPauseResumeRevokeAndNoLoginCredential(t *testing.T) {
	directory := protectedTestDirectory(t)
	keys, err := localkeys.GenerateDeviceKeys("dev")
	mustCLI(t, err)
	managerPublic, managerPrivate, err := ed25519.GenerateKey(rand.Reader)
	mustCLI(t, err)
	managerReceiving, _, err := cryptox.GenerateReceivingKey()
	mustCLI(t, err)
	environmentKey, err := cryptox.GenerateEnvironmentKey()
	mustCLI(t, err)
	grant := cryptox.Grant{AccountID: "acct", AccountGeneration: "1", IssuerDeviceID: "manager", SubjectDeviceID: "dev", SubjectSigningPublicKey: cryptox.EncodeBase64(keys.SigningPublic), SubjectReceivingPublicKey: cryptox.EncodeBase64(keys.ReceivingPublic), EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Role: "rw", ExpiresAt: "0", IdempotencyKey: "grant-1"}
	packet, err := cryptox.WrapEnvironmentKey(environmentKey, cryptox.EnvelopeContext{AccountID: "acct", AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", RecipientType: "device", RecipientID: "dev", RecipientGeneration: "1", RecipientPublicKey: grant.SubjectReceivingPublicKey})
	mustCLI(t, err)
	grant.Envelope = cryptox.EncodeBase64(packet)
	signedGrant, err := cryptox.SignGrant(grant, managerPrivate)
	mustCLI(t, err)
	signing := ed25519.NewKeyFromSeed(keys.SigningSeed)
	mutation := func(sequence uint64, value string) syncclient.Event {
		cipher, err := cryptox.EncryptValue(environmentKey, cryptox.ValueContext{AccountID: "acct", AccountGeneration: "1", EnvironmentID: "env", KeyVersion: "1", Name: "TOKEN"}, []byte(value))
		mustCLI(t, err)
		m, err := cryptox.SignMutation(cryptox.Mutation{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "1", Operation: "put", IdempotencyKey: "write-" + fmtUint(sequence), Name: "TOKEN", Payload: cryptox.EncodeBase64(cipher)}, signing)
		mustCLI(t, err)
		authority := syncclient.SignedGrant{Grant: grant, Signature: signedGrant.Signature}
		return syncclient.Event{Sequence: sequence, Mutation: syncclient.SignedMutation{Mutation: m.Mutation, Signature: m.Signature}, Authorization: &authority}
	}
	events := []syncclient.Event{mutation(1, "before-pause"), mutation(2, "after-resume")}
	var phase atomic.Int32
	var authorizationCalls, fullAfterPause, bootCalls atomic.Int32
	nonce := cryptox.EncodeBase64(make([]byte, 32))
	token := cryptox.EncodeBase64(append([]byte{9}, make([]byte, 31)...))
	expiry := time.Now().Add(time.Minute).Unix()
	proof, err := cryptox.NewDeviceBootProof("acct", "1", "dev", keys.SigningPublic, keys.ReceivingPublic, "boot-1", nonce, fmtUint(uint64(expiry)))
	mustCLI(t, err)
	proofWire, err := proof.SigningBytes()
	mustCLI(t, err)
	var fields []string
	_ = json.Unmarshal(proofWire, &fields)
	var issuerEvidence *cryptox.IssuerRecoveryDAG
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		if strings.HasSuffix(r.URL.Path, "/boot-challenges") {
			bootCalls.Add(1)
			if r.Header.Get("Authorization") != "" {
				t.Error("reboot sent login credential")
			}
			if phase.Load() == 3 {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"error":"device_untrusted"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(syncclient.DeviceChallenge{ChallengeID: "boot-1", Nonce: nonce, ExpiresAt: expiry, SigningPayload: fields})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/boot-sessions") {
			var body struct{ DeviceID, AccountGeneration, ChallengeID, Signature string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if cryptox.VerifyDeviceBootProof(proof, body.Signature, keys.SigningPublic) != nil {
				t.Error("boot possession invalid")
			}
			_ = json.NewEncoder(w).Encode(syncclient.DeviceSession{Token: token, ExpiresAt: time.Now().Add(time.Hour).Unix()})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("pull not using bound device session")
		}
		if phase.Load() == 3 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		sequence := uint64(1)
		if phase.Load() > 0 {
			sequence = 2
		}
		pull := syncclient.Pull{IssuerDAGEvidence: issuerEvidence, AccountID: "acct", AccountGeneration: "1", Sequence: sequence, Grants: []syncclient.SignedGrant{{Grant: grant, Signature: signedGrant.Signature}}, Events: []syncclient.Event{}}
		if r.URL.Query().Get("scope") == "authorizations" {
			authorizationCalls.Add(1)
			pull.Scope = "authorizations"
		} else {
			after := r.URL.Query().Get("after")
			if after == "0" && phase.Load() == 2 {
				fullAfterPause.Add(1)
			}
			for _, event := range events {
				if event.Sequence <= sequence && (after == "0" || after == "1" && event.Sequence > 1) {
					pull.Events = append(pull.Events, event)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(pull)
	}))
	defer server.Close()
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	vault := store.Vault()
	mustCLI(t, vault.SaveDeviceKeys(keys))
	contextFields := pairing.Context{AccountID: "acct", AccountGeneration: "1", Purpose: pairing.PurposeEnrollment, SessionID: "pair-session", ChallengeNonce: nonce, ExpiresAt: fmtUint(uint64(expiry)), InitiatorDeviceID: "dev", InitiatorSigningPublicKey: grant.SubjectSigningPublicKey, InitiatorReceivingPublicKey: grant.SubjectReceivingPublicKey, ApproverDeviceID: "manager", ApproverSigningPublicKey: cryptox.EncodeBase64(managerPublic), ApproverReceivingPublicKey: cryptox.EncodeBase64(managerReceiving)}
	approval := cryptox.EnrollmentApproval{Context: cryptox.EnrollmentContext(contextFields), PairingProfile: pairing.Profile, TranscriptHash: strings.Repeat("a", 64), Grants: []cryptox.SignedGrantWire{cryptox.GrantToWire(signedGrant)}}
	session := localkeys.LoginSession{Endpoint: server.URL, AccountID: "acct", AccountGeneration: 1, Token: cryptox.EncodeBase64(make([]byte, 32)), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	mustCLI(t, vault.SaveSession(session))
	receipt, evidence := signedDaemonReceipt(t, approval, managerPrivate, signing)
	issuerEvidence = evidence
	mustCLI(t, saveReceiptV5(vault, session, keys, receipt, true))
	mustCLI(t, store.Close())
	provider := &isolatedProvider{values: map[string]string{"TOKEN": "original", "UNRELATED": "keep"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "20ms", "--sync-interval", "1s"}, io.Discard, io.Discard, commandRuntime{httpClient: server.Client(), provider: provider})
	}()
	defer func() { cancel(); mustCLI(t, <-done) }()
	endpoint, err := ipcEndpoint(filepath.Join(directory, "ipc"), "", "")
	mustCLI(t, err)
	eventuallyCLI(t, func() bool {
		response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
		return err == nil && response.OK && response.Status.Environments == 1
	})
	if second, err := protectedStore(protectedOptions{directory: directory}); err == nil {
		_ = second.Close()
		t.Fatal("daemon lost exclusive encrypted store ownership")
	}
	_, err = commandTest(t, "activate", "--local-directory", directory, "--environment", "env", "--priority", "4")
	mustCLI(t, err)
	eventuallyCLI(t, func() bool { return provider.value("TOKEN") == "before-pause" })
	_, err = commandTest(t, "pause", "--local-directory", directory)
	mustCLI(t, err)
	phase.Store(1)
	eventuallyCLI(t, func() bool { return authorizationCalls.Load() > 0 })
	if provider.value("TOKEN") != "before-pause" {
		t.Fatal("pause applied shared edit")
	}
	_, err = commandTest(t, "resume", "--local-directory", directory)
	mustCLI(t, err)
	phase.Store(2)
	eventuallyCLI(t, func() bool { return provider.value("TOKEN") == "after-resume" })
	if fullAfterPause.Load() == 0 {
		t.Fatal("resume did not full catchup")
	}
	phase.Store(3)
	eventuallyCLI(t, func() bool { return provider.value("TOKEN") == "original" })
	response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
	mustCLI(t, err)
	if !response.OK || response.Status.AccountGeneration != 0 || provider.value("UNRELATED") != "keep" || bootCalls.Load() < 2 {
		t.Fatal("revocation failed local restore or boot fallback", response)
	}
	_, err = commandTest(t, "logout", "--local-directory", directory)
	mustCLI(t, err)
	_, err = commandTest(t, "status", "--local-directory", directory)
	mustCLI(t, err)
}

func TestProtectedDaemonWithoutTrustIsIdleAndLogoutKeepsIPC(t *testing.T) {
	directory := protectedTestDirectory(t)
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	mustCLI(t, store.Close())
	var network atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")
		network.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "20ms", "--sync-interval", "1s"}, io.Discard, io.Discard, commandRuntime{httpClient: server.Client()})
	}()
	defer func() { cancel(); mustCLI(t, <-done) }()
	endpoint, err := ipcEndpoint(filepath.Join(directory, "ipc"), "", "")
	mustCLI(t, err)
	eventuallyCLI(t, func() bool {
		response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
		return err == nil && response.OK
	})
	_, err = commandTest(t, "logout", "--local-directory", directory)
	mustCLI(t, err)
	_, err = commandTest(t, "status", "--local-directory", directory)
	mustCLI(t, err)
	if network.Load() != 0 {
		t.Fatal("untrusted idle daemon contacted server")
	}
}

func TestDurableLogoutCrashCannotBootOldTrust(t *testing.T) {
	directory := protectedTestDirectory(t)
	store, err := protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	keys, err := localkeys.GenerateDeviceKeys("synthetic-old-device")
	mustCLI(t, err)
	vault := store.Vault()
	mustCLI(t, vault.SaveDeviceKeys(keys))
	mustCLI(t, vault.SaveTrustContext(localkeys.TrustContext{Endpoint: "https://synthetic.invalid", AccountID: "acct", AccountGeneration: 1, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, CertificateVersion: "5", PairingProfile: pairing.Profile, EnrollmentCertificate: []byte(`{"syntheticStorageOnly":true}`), EnrollmentKey: "synthetic-old-enrollment", Accepted: true}))
	mustCLI(t, vault.Save("writes-v1", []byte(`{"syntheticPendingOnly":true}`)))
	engine, err := localstate.New(store)
	mustCLI(t, err)
	mustCLI(t, engine.Logout())
	mustCLI(t, store.Close())
	// 模拟恰在state logout已durable、旧keys/trust/journal尚未清时崩溃。
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "20ms", "--sync-interval", "1s"}, io.Discard, io.Discard, commandRuntime{})
	}()
	endpoint, err := ipcEndpoint(filepath.Join(directory, "ipc"), "", "")
	mustCLI(t, err)
	eventuallyCLI(t, func() bool {
		response, err := localipc.Call(context.Background(), endpoint, localipc.Request{Command: "status"})
		return err == nil && response.OK && response.Status.AccountGeneration == 0
	})
	cancel()
	mustCLI(t, <-done)
	store, err = protectedStore(protectedOptions{directory: directory})
	mustCLI(t, err)
	defer store.Close()
	for _, slot := range []string{"device-v1", "session-v1", "trust-v1", "writes-v1"} {
		if _, err = store.Vault().Load(slot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("logout crash retained old account material", slot, err)
		}
	}
	restored, err := localstate.New(store)
	mustCLI(t, err)
	if !restored.State().AccountClosed {
		t.Fatal("logout tombstone silently unlocked")
	}
}
