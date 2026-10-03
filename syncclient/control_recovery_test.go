package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 此测试验证 DTO/保护 journal 边界；服务端真实接受语义另由 HTTPS/SQLite 联合验收覆盖。
func TestRecoveryControlsTypedEvidenceAndProtectedGrantJournal(t *testing.T) {
	fixture := recoverySource(t)
	trust := recoveryTrust(t, fixture)
	verifier, e := NewRecoveredDevicePinnedVerifier(trust)
	check(t, e)
	defer verifier.Close()
	own := trust.Accepted.Submission.Grants[0]
	proof := trust.Evidence
	cloud, e := verifier.VerifyPull(context.Background(), Pull{Full: true, AccountID: trust.Trust.AccountID, AccountGeneration: "1", Sequence: trust.Accepted.Sequence, Grants: []SignedGrant{{Grant: own.Grant, Signature: own.Signature}}, IssuerRecoveryEvidence: &proof}, localstate.CloudSnapshot{})
	check(t, e)
	engine, e := localstate.New(&volatileStore{state: localstate.EmptyState()})
	check(t, e)
	check(t, engine.AcceptSnapshot(cloud, time.Unix(fixture.Recovery.Now, 0)))
	var fault, posts, wrongCapability atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			posts.Add(1)
			w.WriteHeader(400)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/grant-status") {
			_ = json.NewEncoder(w).Encode(GrantStatus{IdempotencyKey: r.URL.Query().Get("idempotencyKey")})
			return
		}
		if r.URL.Query().Get("capability") != cryptox.RecoveryAuthorityCapability {
			wrongCapability.Add(1)
		}
		candidate := cloneRecoveryEvidence(proof)
		var evidence any = candidate
		switch fault.Load() {
		case 1:
			evidence = cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile}
		case 2:
			candidate.Transitions = []cryptox.AcceptedRecoveryTransition{}
			evidence = candidate
		}
		if strings.HasSuffix(r.URL.Path, "/issuer-evidence") {
			_ = json.NewEncoder(w).Encode(map[string]any{"sequence": cloud.Sequence, "grants": []cryptox.SignedGrantWire{own}, "issuerEvidence": evidence})
			return
		}
		subject := ManagementSubject{DeviceID: own.Grant.SubjectDeviceID, SigningPublicKey: own.Grant.SubjectSigningPublicKey, ReceivingPublicKey: own.Grant.SubjectReceivingPublicKey, CurrentGrant: &own, HighestGrantGeneration: own.Grant.GrantGeneration}
		if fault.Load() == 3 {
			subject.ReceivingPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{11}, 32))
		}
		if fault.Load() == 4 {
			subject.HighestGrantGeneration = "0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accountId": cloud.AccountID, "accountGeneration": "1", "environmentId": own.Grant.EnvironmentID, "sequence": cloud.Sequence, "keyVersion": own.Grant.KeyVersion, "subjects": []ManagementSubject{subject}, "issuerEvidence": evidence})
	}))
	defer server.Close()
	client, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: cloud.AccountID, AccountGeneration: 1, DeviceID: trust.Trust.DeviceID, Token: cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32)), Verifier: verifier, Engine: engine, Now: func() time.Time { return time.Unix(fixture.Recovery.Now, 0) }})
	check(t, e)
	ctx := context.Background()
	control, e := client.EnvironmentControl(ctx, own.Grant.EnvironmentID)
	check(t, e)
	if control.IssuerRecoveryEvidence == nil || control.IssuerEvidence.Profile != "" {
		t.Fatal("recovery control cast into legacy profile")
	}
	_, e = client.VerifyEnvironmentControl(control, own.Grant.EnvironmentID, true)
	check(t, e)
	key := ed25519.NewKeyFromSeed(recoveryTestHex(t, fixture.Recovery.Seeds["deviceEd"]))
	defer clear(key)
	tx, e := client.PrepareGrantUpdate(ctx, GrantUpdateIntent{ID: "recovery-control-update", EnvironmentID: own.Grant.EnvironmentID, SubjectDeviceID: own.Grant.SubjectDeviceID, Role: "ro"}, key)
	check(t, e)
	data, e := tx.ProtectedBytes()
	check(t, e)
	defer clear(data)
	restored, e := client.RestoreGrantUpdate(data)
	check(t, e)
	if restored.ID() != tx.ID() || !sameJSON(restored.ControlCheckpoint(), tx.ControlCheckpoint()) {
		t.Fatal("protected recovery journal changed original source")
	}
	for _, kind := range []int64{1, 2, 3, 4} {
		fault.Store(kind)
		if _, e = client.ManagementControl(ctx, own.Grant.EnvironmentID); e == nil {
			t.Fatalf("invalid typed management evidence accepted: class %d", kind)
		}
	}
	fault.Store(0)
	mixed := control
	mixed.IssuerEvidence = cryptox.IssuerProofV2{Profile: cryptox.IssuerProofV2Profile}
	if _, e = client.VerifyEnvironmentControl(mixed, own.Grant.EnvironmentID, true); e == nil {
		t.Fatal("mixed control profiles accepted")
	}
	if _, e = client.EnvironmentStatusV2(ctx, "never-post-legacy"); e == nil {
		t.Fatal("legacy namespace accepted for recovery client")
	}
	// 默认/显式 false 必须核验 live 检查点；已见更高序号后只有 true 可重验旧 journal。
	future := cloud
	future.Sequence++
	check(t, engine.AcceptSnapshot(future, time.Unix(fixture.Recovery.Now, 0)))
	if _, e = client.VerifyEnvironmentControl(control, own.Grant.EnvironmentID, false); e == nil {
		t.Fatal("explicit false bypassed live checkpoint")
	}
	if _, e = client.VerifyEnvironmentControl(control, own.Grant.EnvironmentID); e == nil {
		t.Fatal("default live control accepted stale checkpoint")
	}
	if _, e = client.VerifyEnvironmentControl(control, own.Grant.EnvironmentID, true); e != nil {
		t.Fatal("historical true rejected exact protected source", e)
	}
	if _, e = client.VerifyEnvironmentControl(control, own.Grant.EnvironmentID, true, false); e == nil {
		t.Fatal("multiple history flags accepted")
	}
	if posts.Load() != 0 || wrongCapability.Load() != 0 {
		t.Fatal("control read issued write or old capability")
	}
}
