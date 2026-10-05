//go:build darwin || linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localipc"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/pairing"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 合成双签回执只验证正式daemon调度；真实PAKE入网由workspace独立验收覆盖。
// 轮询间隔设为一小时，五秒内的下发、暂停授权投影和撤销必须由真实WSS触发。
func TestProtectedDaemonNotificationsWakeLongPollingAndPauseRevoke(t *testing.T) {
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
	events := []syncclient.Event{mutation(1, "before-pause"), mutation(2, "after-resume"), mutation(4, "missed-notification")}
	notificationReady := make(chan *websocket.Conn, 8)
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
		if strings.HasSuffix(r.URL.Path, "/notification-tickets") {
			if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("票据请求绑定错误")
			}
			sequence := uint64(1)
			if phase.Load() == 1 {
				sequence = 2
			}
			if phase.Load() >= 2 {
				sequence = 3
			}
			if phase.Load() == 4 {
				sequence = 4
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ticket": token, "expiresAt": time.Now().Add(30 * time.Second).Unix(), "sequence": sequence})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/notifications") {
			if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("WSS票据未仅使用请求头")
			}
			conn, e := websocket.Accept(w, r, nil)
			if e != nil {
				return
			}
			hint, _ := json.Marshal(syncclient.NotificationHint{AccountID: "acct", AccountGeneration: "1", Sequence: func() uint64 {
				if phase.Load() == 4 {
					return 4
				}
				return 1
			}()})
			_ = conn.Write(context.Background(), websocket.MessageText, hint)
			notificationReady <- conn
			<-conn.CloseRead(context.Background()).Done()
			_ = conn.CloseNow()
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
		if phase.Load() == 1 {
			sequence = 2
		}
		if phase.Load() >= 2 {
			sequence = 3
		}
		if phase.Load() == 4 {
			sequence = 4
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
			afterValue, _ := strconv.ParseUint(after, 10, 64)
			for _, event := range events {
				if event.Sequence <= sequence && (event.Sequence > afterValue) {
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
		done <- runWithRuntime(ctx, []string{"daemon", "--local-directory", directory, "--interval", "20ms", "--sync-interval", "1h"}, io.Discard, io.Discard, commandRuntime{httpClient: server.Client(), provider: provider})
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
	var notification *websocket.Conn
	select {
	case notification = <-notificationReady:
	case <-time.After(3 * time.Second):
		t.Fatal("正式daemon未建立WSS")
	}
	defer notification.CloseNow()
	sendHint := func(seq uint64) {
		t.Helper()
		data, _ := json.Marshal(syncclient.NotificationHint{AccountID: "acct", AccountGeneration: "1", Sequence: seq})
		mustCLI(t, notification.Write(context.Background(), websocket.MessageText, data))
	}
	phase.Store(1)
	sendHint(2)
	eventuallyCLI(t, func() bool { return authorizationCalls.Load() > 0 })
	if provider.value("TOKEN") != "before-pause" {
		t.Fatal("pause applied shared edit")
	}
	_, err = commandTest(t, "resume", "--local-directory", directory)
	mustCLI(t, err)
	phase.Store(2)
	sendHint(3)
	eventuallyCLI(t, func() bool { return provider.value("TOKEN") == "after-resume" })
	if fullAfterPause.Load() == 0 {
		t.Fatal("resume did not full catchup")
	}
	// 连接断开期间服务器接受新值，没有提示；重连必须主动按持久序号补拉。
	_ = notification.CloseNow()
	phase.Store(4)
	select {
	case notification = <-notificationReady:
	case <-time.After(5 * time.Second):
		t.Fatal("正式daemon未退避重连")
	}
	defer notification.CloseNow()
	eventuallyCLI(t, func() bool { return provider.value("TOKEN") == "missed-notification" })
	phase.Store(3)
	go func() { _ = notification.Close(websocket.StatusCode(4003), "authorization_required") }()
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
