package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type originClientFixture struct {
	Approval cryptox.EnrollmentApprovalV5 `json:"approval"`
	Rotation cryptox.EnvironmentChangeV2  `json:"rotation"`
}

func originClientVector(t *testing.T) (originClientFixture, IssuerDAGPinnedTrust, Pull) {
	t.Helper()
	data, e := os.ReadFile("../cryptox/testdata/environment-origin-v1.json")
	check(t, e)
	var f originClientFixture
	check(t, json.Unmarshal(data, &f))
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	d := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	recv := bytes.Repeat([]byte{15}, 32)
	r, e := ecdh.X25519().NewPrivateKey(recv)
	check(t, e)
	a := &f.Approval
	a.Context.InitiatorReceivingPublicKey = cryptox.EncodeBase64(r.PublicKey().Bytes())
	g := a.Grants[0].Grant
	g.SubjectReceivingPublicKey = a.Context.InitiatorReceivingPublicKey
	packet, e := cryptox.WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
	check(t, e)
	g.Envelope = cryptox.EncodeBase64(packet)
	signed, e := cryptox.SignGrant(g, b)
	check(t, e)
	a.Grants = []cryptox.SignedGrantWire{cryptox.GrantToWire(signed)}
	cert, e := a.Certificate()
	check(t, e)
	a.ApproverSignature, e = cryptox.SignEnrollmentCertificateV5(cert, b)
	check(t, e)
	a.InitiatorSignature, e = cryptox.SignEnrollmentCertificateV5(cert, d)
	check(t, e)
	trust := IssuerDAGPinnedTrust{AccountID: g.AccountID, AccountGeneration: 1, DeviceID: g.SubjectDeviceID, DeviceSigningPublicKey: d.Public().(ed25519.PublicKey), ReceivingPrivateKey: recv, Receipt: EnrollmentReceiptV5{IdempotencyKey: "pair-D", Approval: *a}, Now: func() time.Time { return time.Unix(2030000000, 0) }}
	candidate, e := completedEvidenceV5(trust.Receipt)
	check(t, e)
	auth := f.Rotation.Change.Grants[1]
	payload, e := cryptox.EncryptValue(bytes.Repeat([]byte{9}, 32), cryptox.ValueContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, Name: "FIXTURE_VALUE"}, []byte("synthetic-origin-value"))
	check(t, e)
	m, e := cryptox.SignMutation(cryptox.Mutation{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, DeviceID: "device-B", EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, GrantGeneration: auth.Grant.GrantGeneration, Operation: "put", IdempotencyKey: "origin-B-write", Name: "FIXTURE_VALUE", Payload: cryptox.EncodeBase64(payload)}, b)
	check(t, e)
	wa := SignedGrant{Grant: auth.Grant, Signature: auth.Signature}
	pull := Pull{Full: true, AccountID: g.AccountID, AccountGeneration: "1", Sequence: 20, Grants: []SignedGrant{{Grant: g, Signature: signed.Signature}}, IssuerDAGEvidence: &candidate, Events: []Event{{Sequence: 20, Mutation: SignedMutation{Mutation: m.Mutation, Signature: m.Signature}, Authorization: &wa}}}
	return f, trust, pull
}

type failedOriginStore struct {
	volatileStore
	fail bool
}

func (s *failedOriginStore) Save(state localstate.State) error {
	if s.fail {
		return errors.New("synthetic sealed write failure")
	}
	return s.volatileStore.Save(state)
}
func TestIssuerOriginCandidateLedgerAtomicAndRestart(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	store := &failedOriginStore{volatileStore: volatileStore{state: localstate.EmptyState()}}
	engine, e := localstate.New(store)
	check(t, e)
	candidate, e := v.VerifyPull(context.Background(), pull, engine.State().Cloud)
	check(t, e)
	if candidate.Environments["env-fixture"].Values["FIXTURE_VALUE"] != "synthetic-origin-value" || len(candidate.IssuerEvidence) == 0 {
		t.Fatal("verified graph/data missing")
	}
	store.fail = true
	if engine.AcceptDataSnapshotAtEpoch(candidate, trust.Now(), engine.State().SessionEpoch) == nil {
		t.Fatal("sealed failure accepted")
	}
	if engine.State().Cloud.Sequence != 0 || len(engine.State().Cloud.IssuerEvidence) != 0 {
		t.Fatal("partial graph/cache committed")
	}
	store.fail = false
	check(t, engine.AcceptDataSnapshotAtEpoch(candidate, trust.Now(), engine.State().SessionEpoch))
	restarted, e := localstate.New(store)
	check(t, e)
	reopened, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer reopened.Close()
	check(t, reopened.ValidateStoredIssuerEvidence(restarted.State().Cloud))
	before, _ := json.Marshal(engine.State())
	for _, name := range []string{"missing-origin", "unknown-genesis", "wrong-pub", "old-generation", "cycle"} {
		t.Run(name, func(t *testing.T) {
			bad := clonePullOrigin(t, pull)
			switch name {
			case "missing-origin":
				bad.IssuerDAGEvidence.Source.View.Origins = nil
			case "unknown-genesis":
				g := bad.IssuerDAGEvidence.Source.View.Authorities[0].Grant.Grant
				g.EnvironmentID = "unproven-root-Y"
				g.IdempotencyKey = "unproven-Y-genesis"
				a := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
				s, e := cryptox.SignGrant(g, a)
				check(t, e)
				bad.IssuerDAGEvidence.Source.View.Authorities = append(bad.IssuerDAGEvidence.Source.View.Authorities, cryptox.IssuerRecoveryAuthority{Grant: cryptox.GrantToWire(s)})
			case "wrong-pub":
				bad.IssuerDAGEvidence.Source.View.Path[0].Enrollment.Approval.Context.InitiatorReceivingPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{88}, 32))
			case "old-generation":
				bad.IssuerDAGEvidence.AccountGeneration = "2"
			case "cycle":
				h, _ := cryptox.IssuerAuthorityHash(bad.IssuerDAGEvidence.Source.View.Authorities[1].Grant)
				bad.IssuerDAGEvidence.Source.View.Authorities[1].ParentHash = h
			}
			if _, e := v.VerifyPull(context.Background(), bad, engine.State().Cloud); e == nil {
				t.Fatal("bad candidate accepted")
			}
			after, _ := json.Marshal(engine.State())
			if !bytes.Equal(before, after) {
				t.Fatal("failed verification left trusted state")
			}
		})
	}
	corrupt := engine.State().Cloud
	corrupt.IssuerEvidence = []byte(`{"profile":"harmonia/issuer-proof/v2","profile":"attacker"}`)
	if reopened.ValidateStoredIssuerEvidence(corrupt) == nil {
		t.Fatal("restart trusted corrupt ledger")
	}
}
func clonePullOrigin(t *testing.T, p Pull) Pull {
	t.Helper()
	b, e := json.Marshal(p)
	check(t, e)
	var c Pull
	check(t, json.Unmarshal(b, &c))
	c.Full = p.Full
	return c
}
func TestIssuerOriginPauseKeepsDataSequenceAndExecutesRevoke(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	engine := testEngine(t)
	s, e := v.VerifyPull(context.Background(), pull, engine.State().Cloud)
	check(t, e)
	check(t, engine.AcceptDataSnapshotAtEpoch(s, trust.Now(), engine.State().SessionEpoch))
	check(t, engine.SetPaused(true))
	old := engine.State().Cloud
	revoke := pull.Grants[0].Grant
	revoke.Role = "none"
	revoke.Envelope = ""
	revoke.ExpiresAt = "0"
	revoke.GrantGeneration = "2"
	revoke.IdempotencyKey = "origin-revoke-D"
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	sg, e := cryptox.SignGrant(revoke, b)
	check(t, e)
	auth := Pull{Scope: "authorizations", AccountID: pull.AccountID, AccountGeneration: "1", Sequence: 21, Grants: []SignedGrant{{Grant: sg.Grant, Signature: sg.Signature}}}
	projection, e := v.VerifyAuthorizationRefresh(context.Background(), auth, old)
	check(t, e)
	check(t, engine.AcceptAuthorizationRefreshAtEpoch(projection, trust.Now(), engine.State().SessionEpoch))
	current := engine.State().Cloud
	if current.Sequence != old.Sequence || current.AuthorizationSequence != 21 || len(current.Environments) != 0 || len(current.IssuerEvidence) == 0 || !sameJSON(current.SeenMutations, old.SeenMutations) {
		t.Fatal("pause advanced data or lost revoke/evidence")
	}
	check(t, v.ValidateStoredIssuerEvidence(current))
}
func TestIssuerOriginStartupRejectsMissingEvidence(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	st, e := v.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
	check(t, e)
	st.IssuerEvidence = nil
	if v.ValidateStoredIssuerEvidence(st) == nil {
		t.Fatal("cert3 cached data without ledger accepted")
	}
	check(t, v.ValidateStoredIssuerEvidence(localstate.CloudSnapshot{}))
}

func TestIssuerOriginStrictJSONAllProtectedAndHTTPEntrypoints(t *testing.T) {
	_, trust, pull := originClientVector(t)
	receipt, _ := json.Marshal(trust.Receipt)
	approval, _ := json.Marshal(trust.Receipt.Approval)
	evidence, _ := json.Marshal(pull.IssuerDAGEvidence)
	for name, data := range map[string][]byte{"top-duplicate": []byte(`{"profile":"harmonia/issuer-proof/v2","profile":"x"}`), "nested-duplicate": []byte(`{"trustRoot":{"rootDeviceId":"A","rootDeviceId":"B"}}`), "escaped-duplicate": []byte(`{"trustRoot":{"rootDeviceId":"A","rootDevice\u0049d":"B"}}`), "trailing": append(append([]byte(nil), evidence...), []byte(` {}`)...), "invalid-utf8": []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, "depth": []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)), "size": bytes.Repeat([]byte{' '}, cryptox.MaxIssuerProofV2Bytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, e := cryptox.DecodeIssuerRecoveryDAG(data); e == nil {
				t.Fatal("bad protected evidence accepted")
			}
			if cryptox.ValidateStrictJSON(data, cryptox.MaxIssuerProofV2Bytes) == nil {
				t.Fatal("bad bounded JSON accepted")
			}
		})
	}
	for _, data := range [][]byte{append([]byte(`{"idempotencyKey":"pair-D",`), receipt[1:]...), append([]byte(`{"certificateVersion":"3",`), approval[1:]...)} {
		if _, e := DecodeEnrollmentReceiptV5(data); e == nil {
			t.Fatal("bad receipt accepted")
		}
		if _, e := cryptox.DecodeEnrollmentApprovalV5(data); e == nil {
			t.Fatal("bad approval accepted")
		}
	}
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		if r.URL.Query().Get("capability") != cryptox.RecoveryDAGCapability {
			t.Error("missing capability")
		}
		data, _ := json.Marshal(pull)
		_, _ = w.Write(append([]byte(`{"issuerEvidence":null,`), data[1:]...))
	}))
	defer server.Close()
	engine := testEngine(t)
	client, e := New(Config{Endpoint: server.URL, HTTPClient: server.Client(), AccountID: trust.AccountID, AccountGeneration: 1, DeviceID: trust.DeviceID, Token: cryptox.EncodeBase64(make([]byte, 32)), Verifier: v, Engine: engine, Now: trust.Now})
	check(t, e)
	if _, e = client.Pull(context.Background()); e == nil || engine.State().Cloud.Sequence != 0 || len(engine.State().Cloud.IssuerEvidence) > 0 {
		t.Fatal("duplicate HTTP candidate committed")
	}
}

func TestIssuerOriginEmptyRootArraysRoundtripAndNullMissingRejected(t *testing.T) {
	f, trust, _ := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	source := v.genesisAuthorities[0]
	h, _ := cryptox.IssuerAuthorityHash(source)
	root := cloneDAGEvidence(f.Approval.IssuerProof)
	root.Source.View.Path = []cryptox.IssuerRecoveryArchive{}
	root.Source.View.Authorities = []cryptox.IssuerRecoveryAuthority{{Grant: source}}
	root.Source.View.Targets = []cryptox.IssuerTarget{{EnvironmentID: source.Grant.EnvironmentID, AuthorityHash: h}}
	root.Source.View.Origins = []cryptox.SignedEnvironmentOrigin{}
	root.Source.View.IdentityPaths = [][]cryptox.IssuerRecoveryArchive{}
	b, e := json.Marshal(root)
	check(t, e)
	if strings.Contains(string(b), ":null") {
		t.Fatal("producer root zero arrays encoded null")
	}
	decoded, e := cryptox.DecodeIssuerRecoveryDAG(b)
	check(t, e)
	if _, e = cryptox.VerifyIssuerRecoveryDAG(*v.evidenceRoot, decoded); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"path", "authorities", "targets", "origins", "identityPaths"} {
		for _, variant := range []string{"null", "missing"} {
			t.Run(field+"/"+variant, func(t *testing.T) {
				var raw map[string]json.RawMessage
				check(t, json.Unmarshal(b, &raw))
				var sourceMap, view map[string]json.RawMessage
				check(t, json.Unmarshal(raw["source"], &sourceMap))
				check(t, json.Unmarshal(sourceMap["view"], &view))
				if variant == "null" {
					view[field] = json.RawMessage("null")
				} else {
					delete(view, field)
				}
				sourceMap["view"], _ = json.Marshal(view)
				raw["source"], _ = json.Marshal(sourceMap)
				bad, e := json.Marshal(raw)
				check(t, e)
				if _, e = cryptox.DecodeIssuerRecoveryDAG(bad); e == nil {
					t.Fatal("nil/omitted array accepted")
				}
			})
		}
	}
}

func TestIssuerOriginStoredLedgerBindsEveryCachedPermission(t *testing.T) {
	_, trust, pull := originClientVector(t)
	// 本夹具先明确颁发更短的原 RO 授权，随后暂停接收 Admin 升级与
	// 延长期限；两次均由真实父 Admin 签，而不是直接改缓存造正例。
	original := pull.Grants[0].Grant
	original.ExpiresAt = "2030000200"
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	device := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	originalSigned, e := cryptox.SignGrant(original, manager)
	check(t, e)
	trust.Receipt.Approval.Grants = []cryptox.SignedGrantWire{cryptox.GrantToWire(originalSigned)}
	cert, e := trust.Receipt.Approval.Certificate()
	check(t, e)
	trust.Receipt.Approval.ApproverSignature, e = cryptox.SignEnrollmentCertificateV5(cert, manager)
	check(t, e)
	trust.Receipt.Approval.InitiatorSignature, e = cryptox.SignEnrollmentCertificateV5(cert, device)
	check(t, e)
	pull.Grants = []SignedGrant{{Grant: original, Signature: originalSigned.Signature}}
	initial, e := completedEvidenceV5(trust.Receipt)
	check(t, e)
	pull.IssuerDAGEvidence = &initial
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	cache, e := v.VerifyPull(context.Background(), pull, localstate.CloudSnapshot{})
	check(t, e)
	check(t, v.ValidateStoredIssuerEvidence(cache))
	for _, field := range []string{"extra-environment", "key-version", "grant-generation", "role", "expiry", "grant-checkpoint", "fingerprint"} {
		t.Run(field, func(t *testing.T) {
			data, _ := json.Marshal(cache)
			var bad localstate.CloudSnapshot
			check(t, json.Unmarshal(data, &bad))
			env := bad.Environments["env-fixture"]
			switch field {
			case "extra-environment":
				env.ID = "unproven-cached-Y"
				bad.Environments[env.ID] = env
			case "key-version":
				env.KeyVersion++
			case "grant-generation":
				env.GrantGeneration++
			case "role":
				env.Role = localstate.Admin
			case "expiry":
				env.ExpiresAt = nil
			case "grant-checkpoint":
				bad.GrantCheckpoints[env.ID]++
			case "fingerprint":
				bad.GrantFingerprints[env.ID] = strings.Repeat("0", 64)
			}
			if field != "extra-environment" {
				bad.Environments[env.ID] = env
			}
			if v.ValidateStoredIssuerEvidence(bad) == nil {
				t.Fatal("valid graph accepted cache beyond its own exact target")
			}
		})
	}
	// 暂停期间收到更大当前授权，只保存其来源并更新授权检查点，缓存
	// 仍保持原来的低角色与短期限。它是合法的严格安全投影。
	g := pull.Grants[0].Grant
	g.GrantGeneration = "2"
	g.Role = "admin"
	g.ExpiresAt = "2030000300"
	g.IdempotencyKey = "origin-D-upgrade"
	packet, e := cryptox.WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
	check(t, e)
	g.Envelope = cryptox.EncodeBase64(packet)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	sg, e := cryptox.SignGrant(g, b)
	check(t, e)
	p := cloneDAGEvidence(*pull.IssuerDAGEvidence)
	parent := ""
	for _, n := range p.Source.View.Authorities {
		if n.Grant.Grant.SubjectDeviceID == trust.DeviceID {
			parent = n.ParentHash
		}
	}
	p.Source.View.Authorities = append(p.Source.View.Authorities, cryptox.IssuerRecoveryAuthority{Grant: cryptox.GrantToWire(sg), ParentHash: parent})
	h, e := cryptox.IssuerAuthorityHash(cryptox.GrantToWire(sg))
	check(t, e)
	p.Source.View.Targets = []cryptox.IssuerTarget{{EnvironmentID: g.EnvironmentID, AuthorityHash: h}}
	auth := Pull{AccountID: pull.AccountID, AccountGeneration: "1", Scope: "authorizations", Sequence: 21, Grants: []SignedGrant{{Grant: g, Signature: sg.Signature}}, IssuerDAGEvidence: &p}
	projected, e := v.VerifyAuthorizationRefresh(context.Background(), auth, cache)
	check(t, e)
	if projected.Environments[g.EnvironmentID].Role != localstate.ReadOnly || projected.Environments[g.EnvironmentID].ExpiresAt == nil || projected.Environments[g.EnvironmentID].ExpiresAt.Unix() >= 2030000300 || projected.Sequence != cache.Sequence {
		t.Fatal("authorization projection upgraded paused cache")
	}
	check(t, v.ValidateStoredIssuerEvidence(projected))
}
