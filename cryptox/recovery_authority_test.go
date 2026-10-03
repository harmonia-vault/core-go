package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recoveryAuthorityFixture struct {
	SyntheticNow         int64                      `json:"syntheticNow"`
	SyntheticSeeds       map[string]string          `json:"syntheticSeedsHex"`
	RootPin              PinnedIssuerRoot           `json:"rootPin"`
	Original             OriginalInitialization     `json:"originalInitialization"`
	OldCode              AcceptedRecoveryTransition `json:"oldRecoveryTransition"`
	AllAdmin             AcceptedRecoveryTransition `json:"allAdminTransition"`
	Reanchor             AcceptedRecoveryTransition `json:"managerReanchor"`
	Device               AcceptedRecoveredDevice    `json:"recoveredDevice"`
	InitializationHash   string                     `json:"initializationHash"`
	TransitionSigningHex string                     `json:"transitionSigningHex"`
	TransitionHash       string                     `json:"transitionHash"`
	AdminSigningHex      string                     `json:"allAdminSigningHex"`
	AdminHash            string                     `json:"allAdminHash"`
	ReanchorSigningHex   string                     `json:"reanchorSigningHex"`
	ReanchorHash         string                     `json:"reanchorHash"`
	DeviceSigningHex     string                     `json:"deviceSigningHex"`
	DeviceHash           string                     `json:"deviceHash"`
}

func recoveryCheck(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func recoveryClone[T any](t *testing.T, in T) T {
	t.Helper()
	b, e := json.Marshal(in)
	recoveryCheck(t, e)
	var out T
	recoveryCheck(t, json.Unmarshal(b, &out))
	return out
}
func makeRecoveryAuthorityFixture(t *testing.T) recoveryAuthorityFixture {
	t.Helper()
	f := makeOriginFixture(t)
	p := f.Approval.IssuerProof
	now := time.Unix(f.SyntheticNow, 0)
	pin := originPin(f)
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	oldKeys, e := DeriveRecoveryKeys(bytes.Repeat([]byte{66}, 32), pin.AccountID, pin.AccountGeneration, "1")
	recoveryCheck(t, e)
	newKeys, e := DeriveRecoveryKeys(bytes.Repeat([]byte{67}, 32), pin.AccountID, pin.AccountGeneration, "2")
	recoveryCheck(t, e)
	thirdKeys, e := DeriveRecoveryKeys(bytes.Repeat([]byte{68}, 32), pin.AccountID, pin.AccountGeneration, "3")
	recoveryCheck(t, e)
	root := TrustRoot{RootDeviceID: pin.DeviceID, RootSigningPublicKey: pin.SigningPublicKey, RootReceivingPublicKey: pin.ReceivingPublicKey, RecoveryGeneration: "1", RecoverySigningPublicKey: EncodeBase64(oldKeys.SigningPublic), RecoveryReceivingPublicKey: EncodeBase64(oldKeys.ReceivingPublic)}
	root, e = SignTrustRoot(pin.AccountID, "1", root, oldKeys.SigningPrivate)
	recoveryCheck(t, e)
	p.TrustRoot = root
	var initial SignedGrantWire
	for _, a := range p.Authorities {
		if a.ParentHash == "" {
			initial = a.Grant
		}
	}
	recoveryPacket, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: pin.AccountID, AccountGeneration: "1", EnvironmentID: initial.Grant.EnvironmentID, KeyVersion: "1", RecipientType: "recovery", RecipientID: pin.AccountID, RecipientGeneration: "1", RecipientPublicKey: root.RecoveryReceivingPublicKey})
	recoveryCheck(t, e)
	proposal := InitializationProposal{IdempotencyKey: "original-init", Device: InitializationDevice{ID: pin.DeviceID, SigningPublicKey: pin.SigningPublicKey, ReceivingPublicKey: pin.ReceivingPublicKey}, RecoveryGeneration: "1", RecoverySigningPublicKey: root.RecoverySigningPublicKey, RecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, TrustRootSignature: root.Signature, Environments: []InitializationEnvironment{{EnvironmentID: initial.Grant.EnvironmentID, KeyVersion: "1", RecoveryEnvelope: EncodeBase64(recoveryPacket), Grant: initial}}}
	ph, e := proposal.Hash(pin.AccountID, "1")
	recoveryCheck(t, e)
	proof, e := NewInitializationProof(pin.AccountID, "1", "synthetic-init-bearer", "init-challenge", EncodeBase64(bytes.Repeat([]byte{70}, 32)), "2030000100", ph)
	recoveryCheck(t, e)
	dsig, e := SignInitializationProof(proof, rootKey)
	recoveryCheck(t, e)
	rsig, e := SignInitializationProof(proof, oldKeys.SigningPrivate)
	recoveryCheck(t, e)
	o := OriginalInitialization{Proposal: proposal, Proof: proof, DeviceSignature: dsig, RecoverySignature: rsig, Sequence: 1}
	v, e := VerifyRecoveryInitialization(pin, o)
	recoveryCheck(t, e)
	manifest := []RecoveryEnvironmentVersion{{EnvironmentID: initial.Grant.EnvironmentID, KeyVersion: "2"}, {EnvironmentID: "environment-Y", KeyVersion: "1"}}
	newRoot := root
	newRoot.RecoveryGeneration = "2"
	newRoot.RecoverySigningPublicKey = EncodeBase64(newKeys.SigningPublic)
	newRoot.RecoveryReceivingPublicKey = EncodeBase64(newKeys.ReceivingPublic)
	newRoot, e = SignTrustRoot(pin.AccountID, "1", newRoot, newKeys.SigningPrivate)
	recoveryCheck(t, e)
	envelopes := []RecoveryEnvelope{}
	for _, r := range manifest {
		packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: pin.AccountID, AccountGeneration: "1", EnvironmentID: r.EnvironmentID, KeyVersion: r.KeyVersion, RecipientType: "recovery", RecipientID: pin.AccountID, RecipientGeneration: "2", RecipientPublicKey: newRoot.RecoveryReceivingPublicKey})
		recoveryCheck(t, e)
		envelopes = append(envelopes, RecoveryEnvelope{EnvironmentID: r.EnvironmentID, KeyVersion: r.KeyVersion, Envelope: EncodeBase64(packet)})
	}
	mh, e := RecoveryManifestHash(manifest)
	recoveryCheck(t, e)
	eh, e := RecoveryTransitionEnvelopesHash(envelopes)
	recoveryCheck(t, e)
	rh, e := RecoveryTrustRootReferenceHash(pin.AccountID, "1", newRoot)
	recoveryCheck(t, e)
	s := RecoveryTransitionSubmission{Transition: RecoveryAuthorityTransition{AccountID: pin.AccountID, AccountGeneration: "1", OperationID: "transition-old", ChallengeID: "transition-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{71}, 32)), ExpiresAt: "2030000100", SessionHash: strings.Repeat("a", 64), ExpectedSequence: "20", PreviousTransitionHash: v.HeadHash(), OldRecoveryGeneration: "1", OldRecoverySigningPublicKey: root.RecoverySigningPublicKey, OldRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, NewRecoveryGeneration: "2", NewRecoverySigningPublicKey: newRoot.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: newRoot.RecoveryReceivingPublicKey, AuthorizationKind: "old-recovery", EnvironmentManifestHash: mh, EnvelopesHash: eh, NewTrustRootHash: rh, ChainMode: "continuous"}, EnvironmentManifest: manifest, AuthoritySet: []RecoveryAdminAuthority{}, Envelopes: envelopes, NewTrustRoot: newRoot}
	s.AuthorizationSignature, e = SignOldRecoveryTransition(v, s, oldKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	s.NewRecoverySignature, e = SignNewRecoveryTransition(v, s, newKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	oldRecord := AcceptedRecoveryTransition{Submission: s, Sequence: 21}
	advanced, e := VerifyAcceptedRecoveryTransition(v, oldRecord)
	recoveryCheck(t, e)
	// B 的两项 Admin 来自完整原初始化/已接受 origin，不能以 B 的身份
	// 或 X 的单项 Admin 冒充全账号权限。
	p.Targets = []IssuerTarget{}
	adminRows := []RecoveryAdminAuthority{}
	for _, row := range manifest {
		for _, a := range p.Authorities {
			g := a.Grant.Grant
			if g.EnvironmentID == row.EnvironmentID && g.KeyVersion == row.KeyVersion && g.SubjectDeviceID == "device-B" {
				h, e := IssuerAuthorityHash(a.Grant)
				recoveryCheck(t, e)
				p.Targets = append(p.Targets, IssuerTarget{EnvironmentID: g.EnvironmentID, AuthorityHash: h})
				adminRows = append(adminRows, RecoveryAdminAuthority{EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, GrantGeneration: g.GrantGeneration, ExpiresAt: g.ExpiresAt, AuthorityHash: h})
			}
		}
	}
	admin := recoveryClone(t, s)
	admin.Transition.OperationID = "transition-admin"
	admin.Transition.AuthorizationKind = "all-environments-admin"
	admin.Transition.AuthorizerDeviceID = "device-B"
	admin.AuthoritySet = adminRows
	admin.IssuerEvidence = &p
	admin.Transition.AuthoritySetHash, e = RecoveryAdminAuthoritiesHash(adminRows)
	recoveryCheck(t, e)
	admin.Transition.IssuerEvidenceHash, e = RecoveryIssuerEvidenceHash(p)
	recoveryCheck(t, e)
	admin.AuthorizationSignature, e = SignAllAdminRecoveryTransition(v, admin, manager, now)
	recoveryCheck(t, e)
	admin.NewRecoverySignature, e = SignNewRecoveryTransition(v, admin, newKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	adminRecord := AcceptedRecoveryTransition{Submission: admin, Sequence: 21}
	_, e = VerifyAcceptedRecoveryTransition(v, adminRecord)
	recoveryCheck(t, e)
	// 旧 v1 new-only 记录只能作为差异材料。当前码不能绕过连续链缺口；
	// 由 B 的全环境 Admin 明确签 manager-reanchor 才能建立新连接。
	legacyRootHash, e := newRoot.Hash(pin.AccountID, "1")
	recoveryCheck(t, e)
	legacyEnvHash, e := RecoveryEnvelopesHash(envelopes)
	recoveryCheck(t, e)
	legacyProof := RecoveryRotationProof{AccountID: pin.AccountID, AccountGeneration: "1", SessionHash: strings.Repeat("b", 64), RecoveryGeneration: "1", ChallengeID: "legacy-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{72}, 32)), ExpiresAt: "2030000100", NewRecoveryGeneration: "2", NewRecoverySigningPublicKey: newRoot.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: newRoot.RecoveryReceivingPublicKey, EnvelopesHash: legacyEnvHash, TrustRootHash: legacyRootHash}
	legacySig, e := SignRecoveryRotationProof(legacyProof, newKeys.SigningPrivate)
	recoveryCheck(t, e)
	lb, e := legacyProof.SigningBytes()
	recoveryCheck(t, e)
	legacy := RecoveryLegacyState{RecoveryGeneration: "2", RecoverySigningPublicKey: newRoot.RecoverySigningPublicKey, RecoveryReceivingPublicKey: newRoot.RecoveryReceivingPublicKey, TrustRoot: newRoot, Rotations: []RecoveryLegacyRotation{{IdempotencyKey: "legacy-v1", SigningBytes: EncodeBase64(lb), Signature: legacySig, Sequence: 14}}}
	reanchor := recoveryClone(t, admin)
	reanchor.Transition.OperationID = "transition-reanchor"
	reanchor.Transition.ExpectedSequence = "21"
	reanchor.Transition.ChainMode = "manager-reanchor"
	reanchor.Transition.OldRecoveryGeneration = "2"
	reanchor.Transition.OldRecoverySigningPublicKey = newRoot.RecoverySigningPublicKey
	reanchor.Transition.OldRecoveryReceivingPublicKey = newRoot.RecoveryReceivingPublicKey
	reanchor.Transition.NewRecoveryGeneration = "3"
	reanchor.Transition.NewRecoverySigningPublicKey = EncodeBase64(thirdKeys.SigningPublic)
	reanchor.Transition.NewRecoveryReceivingPublicKey = EncodeBase64(thirdKeys.ReceivingPublic)
	reanchor.LegacyState = &legacy
	reanchor.NewTrustRoot.RecoveryGeneration = "3"
	reanchor.NewTrustRoot.RecoverySigningPublicKey = reanchor.Transition.NewRecoverySigningPublicKey
	reanchor.NewTrustRoot.RecoveryReceivingPublicKey = reanchor.Transition.NewRecoveryReceivingPublicKey
	reanchor.NewTrustRoot, e = SignTrustRoot(pin.AccountID, "1", reanchor.NewTrustRoot, thirdKeys.SigningPrivate)
	recoveryCheck(t, e)
	reanchor.Transition.LegacyStateHash, e = legacy.Hash(pin.AccountID, "1")
	recoveryCheck(t, e)
	reanchor.Transition.NewTrustRootHash, e = RecoveryTrustRootReferenceHash(pin.AccountID, "1", reanchor.NewTrustRoot)
	recoveryCheck(t, e)
	reanchor.Envelopes = []RecoveryEnvelope{}
	for _, row := range manifest {
		packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: pin.AccountID, AccountGeneration: "1", EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, RecipientType: "recovery", RecipientID: pin.AccountID, RecipientGeneration: "3", RecipientPublicKey: reanchor.NewTrustRoot.RecoveryReceivingPublicKey})
		recoveryCheck(t, e)
		reanchor.Envelopes = append(reanchor.Envelopes, RecoveryEnvelope{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, Envelope: EncodeBase64(packet)})
	}
	reanchor.Transition.EnvelopesHash, e = RecoveryTransitionEnvelopesHash(reanchor.Envelopes)
	recoveryCheck(t, e)
	reanchor.IssuerEvidence.TrustRoot = newRoot
	reanchor.Transition.IssuerEvidenceHash, e = RecoveryIssuerEvidenceHash(*reanchor.IssuerEvidence)
	recoveryCheck(t, e)
	reanchor.AuthorizationSignature, e = SignAllAdminRecoveryTransition(v, reanchor, manager, now)
	recoveryCheck(t, e)
	reanchor.NewRecoverySignature, e = SignNewRecoveryTransition(v, reanchor, thirdKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	reanchorRecord := AcceptedRecoveryTransition{Submission: reanchor, Sequence: 22}
	_, e = VerifyAcceptedRecoveryTransition(v, reanchorRecord)
	recoveryCheck(t, e)
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	receiving, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{16}, 32))
	recoveryCheck(t, e)
	devicePub := EncodeBase64(deviceKey.Public().(ed25519.PublicKey))
	receivingPub := EncodeBase64(receiving.PublicKey().Bytes())
	packet, e := WrapEnvironmentKey(bytes.Repeat([]byte{9}, 32), EnvelopeContext{AccountID: pin.AccountID, AccountGeneration: "1", EnvironmentID: "environment-Y", KeyVersion: "1", RecipientType: "device", RecipientID: "recovered-E", RecipientGeneration: "1", RecipientPublicKey: receivingPub})
	recoveryCheck(t, e)
	g, e := SignGrant(Grant{AccountID: pin.AccountID, AccountGeneration: "1", EnvironmentID: "environment-Y", KeyVersion: "1", IssuerDeviceID: "recovered-E", SubjectDeviceID: "recovered-E", SubjectSigningPublicKey: devicePub, SubjectReceivingPublicKey: receivingPub, Role: "admin", ExpiresAt: "0", GrantGeneration: "1", IdempotencyKey: "recovery-self-Y", Envelope: EncodeBase64(packet)}, deviceKey)
	recoveryCheck(t, e)
	deviceProof := recoveryClone(t, p)
	deviceProof.TrustRoot = newRoot
	ds := RecoveredDeviceSubmission{CertificateVersion: "4", Capabilities: []string{RecoveryAuthorityCapability}, Enrollment: RecoveredDeviceEnrollment{AccountID: pin.AccountID, AccountGeneration: "1", RecoveryGeneration: "2", RecoveryTransitionHash: advanced.HeadHash(), OperationID: "recover-device-E", ChallengeID: "recover-device-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{73}, 32)), ExpiresAt: "2030000100", RestrictedSessionHash: strings.Repeat("c", 64), ExpectedSequence: "30", DeviceID: "recovered-E", DeviceSigningPublicKey: devicePub, DeviceReceivingPublicKey: receivingPub}, SelectedRights: []RecoveredDeviceRight{{EnvironmentID: "environment-Y", KeyVersion: "1", Role: "admin", ExpiresAt: "0"}}, Grants: []SignedGrantWire{GrantToWire(g)}, IssuerEvidence: deviceProof, Envelopes: []RecoveryEnvelope{{EnvironmentID: "environment-Y", KeyVersion: "1", Envelope: g.Grant.Envelope}}}
	ds.Enrollment.SelectedRightsHash, e = RecoveredDeviceRightsHash(ds.SelectedRights)
	recoveryCheck(t, e)
	ds.Enrollment.GrantsHash, e = RecoveredDeviceGrantsHash(ds.Grants)
	recoveryCheck(t, e)
	ds.Enrollment.EnvelopesHash, e = RecoveredDeviceEnvelopesHash(ds.Envelopes)
	recoveryCheck(t, e)
	ds.Enrollment.IssuerEvidenceHash, e = RecoveryIssuerEvidenceHash(ds.IssuerEvidence)
	recoveryCheck(t, e)
	ds.RecoverySignature, e = SignRecoveredDeviceByRecovery(advanced, ds, newKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	ds.DeviceSignature, e = SignRecoveredDeviceAfterHPKE(advanced, ds, deviceKey, receiving.Bytes(), now)
	recoveryCheck(t, e)
	deviceRecord := AcceptedRecoveredDevice{Submission: ds, Sequence: 31}
	_, e = VerifyAcceptedRecoveredDevice(advanced, deviceRecord)
	recoveryCheck(t, e)
	ih, e := o.Hash()
	recoveryCheck(t, e)
	tb, e := s.Transition.SigningBytes()
	recoveryCheck(t, e)
	th, e := RecoveryTransitionHash(s)
	recoveryCheck(t, e)
	ab, e := admin.Transition.SigningBytes()
	recoveryCheck(t, e)
	ah, e := RecoveryTransitionHash(admin)
	recoveryCheck(t, e)
	reb, e := reanchor.Transition.SigningBytes()
	recoveryCheck(t, e)
	reh, e := RecoveryTransitionHash(reanchor)
	recoveryCheck(t, e)
	db, e := ds.Enrollment.SigningBytes()
	recoveryCheck(t, e)
	dh, e := RecoveredDeviceReferenceHash(ds)
	recoveryCheck(t, e)
	return recoveryAuthorityFixture{SyntheticNow: f.SyntheticNow, SyntheticSeeds: map[string]string{"rootEd": strings.Repeat("01", 32), "managerEd": strings.Repeat("02", 32), "oldRecovery": strings.Repeat("42", 32), "newRecovery": strings.Repeat("43", 32), "thirdRecovery": strings.Repeat("44", 32), "deviceEd": strings.Repeat("06", 32), "deviceX": strings.Repeat("10", 32)}, RootPin: pin, Original: o, OldCode: oldRecord, AllAdmin: adminRecord, Reanchor: reanchorRecord, Device: deviceRecord, InitializationHash: ih, TransitionSigningHex: hex.EncodeToString(tb), TransitionHash: th, AdminSigningHex: hex.EncodeToString(ab), AdminHash: ah, ReanchorSigningHex: hex.EncodeToString(reb), ReanchorHash: reh, DeviceSigningHex: hex.EncodeToString(db), DeviceHash: dh}
}
func TestRecoveryAuthorityContinuousAndAllAdminPositive(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	for _, r := range []AcceptedRecoveryTransition{f.OldCode, f.AllAdmin, f.Reanchor} {
		advanced, e := VerifyAcceptedRecoveryTransition(v, r)
		recoveryCheck(t, e)
		if advanced.Generation() != r.Submission.Transition.NewRecoveryGeneration || advanced.HeadHash() == v.HeadHash() {
			t.Fatal("transition did not advance exact trusted head")
		}
	}
	advanced, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	d, e := VerifyAcceptedRecoveredDevice(advanced, f.Device)
	recoveryCheck(t, e)
	recoveryCheck(t, d.VerifySourceGrant(f.Device.Submission.Grants[0]))
	other := f.Device.Submission.Grants[0]
	other.Grant.EnvironmentID = "unselected-X"
	if d.VerifySourceGrant(other) == nil {
		t.Fatal("recovery source escaped selected environment")
	}
	if os.Getenv("HARMONIA_WRITE_SYNTHETIC_RECOVERY_VECTOR") == "1" {
		data, e := json.MarshalIndent(f, "", "  ")
		recoveryCheck(t, e)
		data = append(data, '\n')
		if strings.Contains(strings.ToLower(string(data)), "sk-") {
			t.Fatal("synthetic vector accidentally matches API prefix; regenerate synthetic packet")
		}
		for _, path := range []string{"testdata/recovery-authority-v1.json", "../../protocol/vectors/recovery-authority-v1.json"} {
			recoveryCheck(t, os.WriteFile(path, data, 0644))
		}
	}
}
func TestRecoveryAuthorityRejectsSignedBindingsAndMissingConsent(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	for _, field := range []string{"account", "generation", "operation", "challenge", "nonce", "session", "expiry", "old-generation", "old-public", "new-public", "head", "expected", "manifest", "envelope", "root", "signature", "new-signature"} {
		t.Run(field, func(t *testing.T) {
			bad := recoveryClone(t, f.OldCode)
			s := &bad.Submission
			switch field {
			case "account":
				s.Transition.AccountID = "other-account"
			case "generation":
				s.Transition.AccountGeneration = "2"
			case "operation":
				s.Transition.OperationID += "-changed"
			case "challenge":
				s.Transition.ChallengeID += "-changed"
			case "nonce":
				s.Transition.Nonce = EncodeBase64(bytes.Repeat([]byte{99}, 32))
			case "session":
				s.Transition.SessionHash = strings.Repeat("f", 64)
			case "expiry":
				s.Transition.ExpiresAt = "2030000101"
			case "old-generation":
				s.Transition.OldRecoveryGeneration = "2"
			case "old-public":
				s.Transition.OldRecoverySigningPublicKey = s.Transition.NewRecoverySigningPublicKey
			case "new-public":
				s.Transition.NewRecoveryReceivingPublicKey = f.RootPin.ReceivingPublicKey
			case "head":
				s.Transition.PreviousTransitionHash = strings.Repeat("f", 64)
			case "expected":
				s.Transition.ExpectedSequence = "21"
			case "manifest":
				s.EnvironmentManifest = s.EnvironmentManifest[:1]
			case "envelope":
				s.Envelopes[0].Envelope = EncodeBase64(make([]byte, 80))
			case "root":
				s.NewTrustRoot.RootDeviceID = "server-replacement-root"
			case "signature":
				s.AuthorizationSignature = ""
			case "new-signature":
				s.NewRecoverySignature = ""
			}
			if _, e := VerifyAcceptedRecoveryTransition(v, bad); e == nil {
				t.Fatal("changed transition accepted")
			}
		})
	}
	oldKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["oldRecovery"]), f.RootPin.AccountID, "1", "1")
	recoveryCheck(t, e)
	newKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["newRecovery"]), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, e)
	unsigned := recoveryClone(t, f.OldCode.Submission)
	unsigned.AuthorizationSignature = ""
	if _, e := SignNewRecoveryTransition(v, unsigned, newKeys.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("new key blindly signed without old consent")
	}
	if _, e := SignOldRecoveryTransition(v, f.OldCode.Submission, newKeys.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("new key masqueraded as old authority")
	}
	if _, e := SignOldRecoveryTransition(v, f.OldCode.Submission, oldKeys.SigningPrivate, time.Unix(f.SyntheticNow+121, 0)); e == nil {
		t.Fatal("expired challenge signed")
	}
	if _, e := VerifyAcceptedRecoveryTransition(v, AcceptedRecoveryTransition{Submission: f.OldCode.Submission, Sequence: 22}); e == nil {
		t.Fatal("different accepted sequence allowed")
	}
}
func TestRecoveryAuthorityAllAdminCannotUsePartialOrOldV1Code(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	manager := ed25519.NewKeyFromSeed(mustHex(t, f.SyntheticSeeds["managerEd"]))
	for _, field := range []string{"missing-authority", "missing-target", "wrong-generation", "wrong-expiry", "wrong-actor", "missing-proof", "new-genesis"} {
		t.Run(field, func(t *testing.T) {
			s := recoveryClone(t, f.AllAdmin.Submission)
			switch field {
			case "missing-authority":
				s.AuthoritySet = s.AuthoritySet[:1]
			case "missing-target":
				s.IssuerEvidence.Targets = s.IssuerEvidence.Targets[:1]
			case "wrong-generation":
				s.AuthoritySet[0].GrantGeneration = "3"
			case "wrong-expiry":
				s.AuthoritySet[0].ExpiresAt = "0"
			case "wrong-actor":
				s.Transition.AuthorizerDeviceID = f.RootPin.DeviceID
			case "missing-proof":
				s.IssuerEvidence = nil
			case "new-genesis":
				g := f.Original.Proposal.Environments[0].Grant.Grant
				g.EnvironmentID = "unknown-genesis"
				g.IdempotencyKey = "fake-init-Y"
				key := ed25519.NewKeyFromSeed(mustHex(t, f.SyntheticSeeds["rootEd"]))
				signed, e := SignGrant(g, key)
				recoveryCheck(t, e)
				s.IssuerEvidence.Authorities = append(s.IssuerEvidence.Authorities, IssuerAuthorityV2{Grant: GrantToWire(signed)})
			}
			if _, e := SignAllAdminRecoveryTransition(v, s, manager, time.Unix(f.SyntheticNow, 0)); e == nil {
				t.Fatal("partial/directory-derived management allowed")
			}
		})
	}
	s := recoveryClone(t, f.Reanchor.Submission)
	s.Transition.AuthorizationKind = "old-recovery"
	s.Transition.AuthorizerDeviceID = ""
	s.Transition.AuthoritySetHash = ""
	s.Transition.IssuerEvidenceHash = ""
	s.AuthoritySet = []RecoveryAdminAuthority{}
	s.IssuerEvidence = nil
	current, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["newRecovery"]), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, e)
	if _, e := SignOldRecoveryTransition(v, s, current.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("v1 current code established root TOFU")
	}
}
func TestRecoveredDeviceRequiresRotationExactRightsAndRealHPKE(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	advanced, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	key := ed25519.NewKeyFromSeed(mustHex(t, f.SyntheticSeeds["deviceEd"]))
	receiving := mustHex(t, f.SyntheticSeeds["deviceX"])
	if _, e := SignRecoveredDeviceAfterHPKE(v, f.Device.Submission, key, receiving, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("initial unrotated recovery gained device trust")
	}
	for _, field := range []string{"role", "expiry", "environment", "receiving", "signing", "generation", "head", "session", "nonce", "profile", "capability", "missing-recovery-signature", "device-signature"} {
		t.Run(field, func(t *testing.T) {
			r := recoveryClone(t, f.Device)
			s := &r.Submission
			switch field {
			case "role":
				s.SelectedRights[0].Role = "ro"
			case "expiry":
				s.SelectedRights[0].ExpiresAt = "2030000300"
			case "environment":
				s.SelectedRights[0].EnvironmentID = "unselected-X"
			case "receiving":
				s.Enrollment.DeviceReceivingPublicKey = f.RootPin.ReceivingPublicKey
			case "signing":
				s.Enrollment.DeviceSigningPublicKey = f.RootPin.SigningPublicKey
			case "generation":
				s.Enrollment.RecoveryGeneration = "1"
			case "head":
				s.Enrollment.RecoveryTransitionHash = strings.Repeat("f", 64)
			case "session":
				s.Enrollment.RestrictedSessionHash = strings.Repeat("f", 64)
			case "nonce":
				s.Enrollment.Nonce = EncodeBase64(bytes.Repeat([]byte{90}, 32))
			case "profile":
				s.CertificateVersion = "3"
			case "capability":
				s.Capabilities = []string{}
			case "missing-recovery-signature":
				s.RecoverySignature = ""
			case "device-signature":
				s.DeviceSignature = ""
			}
			if _, e := VerifyAcceptedRecoveredDevice(advanced, r); e == nil {
				t.Fatal("changed recovery certificate accepted")
			}
		})
	}
	bad := recoveryClone(t, f.Device.Submission)
	bad.Grants[0].Grant.Envelope = EncodeBase64(make([]byte, 80))
	g, e := SignGrant(bad.Grants[0].Grant, key)
	recoveryCheck(t, e)
	bad.Grants[0] = GrantToWire(g)
	bad.Envelopes[0].Envelope = g.Grant.Envelope
	bad.Enrollment.GrantsHash, e = RecoveredDeviceGrantsHash(bad.Grants)
	recoveryCheck(t, e)
	bad.Enrollment.EnvelopesHash, e = RecoveredDeviceEnvelopesHash(bad.Envelopes)
	recoveryCheck(t, e)
	newKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["newRecovery"]), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, e)
	bad.RecoverySignature, e = SignRecoveredDeviceByRecovery(advanced, bad, newKeys.SigningPrivate, time.Unix(f.SyntheticNow, 0))
	recoveryCheck(t, e)
	if _, e := SignRecoveredDeviceAfterHPKE(advanced, bad, key, receiving, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("device signed without opening all HPKE")
	}
}

func TestRecoveryAuthorityStrictShapeAndReplay(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	valid, _ := json.Marshal(f.OldCode.Submission)
	device, _ := json.Marshal(f.Device.Submission)
	_, err := DecodeRecoveryTransitionSubmission(valid)
	recoveryCheck(t, err)
	_, err = DecodeRecoveredDeviceSubmission(device)
	recoveryCheck(t, err)
	cases := map[string][]byte{
		"duplicate-top":        append([]byte(`{"authoritySet":[],`), valid[1:]...),
		"duplicate-nested":     bytes.Replace(valid, []byte(`"chainMode":"continuous"`), []byte(`"chainMode":"continuous","chainMode":"continuous"`), 1),
		"unknown-top":          append([]byte(`{"secret":"synthetic-forbidden",`), valid[1:]...),
		"trailing":             append(append([]byte(nil), valid...), []byte(`{}`)...),
		"invalid-utf8":         append(append([]byte(nil), valid...), 0xff),
		"too-large":            append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), MaxRecoveryAuthorityBytes)...),
		"too-deep":             []byte(strings.Repeat("[", 70) + strings.Repeat("]", 70)),
		"missing-empty-string": bytes.Replace(valid, []byte(`"authorizerDeviceId":"",`), nil, 1),
		"null-empty-string":    bytes.Replace(valid, []byte(`"authorizerDeviceId":""`), []byte(`"authorizerDeviceId":null`), 1),
		"missing-null":         bytes.Replace(valid, []byte(`"issuerEvidence":null,`), nil, 1),
		"null-array":           bytes.Replace(valid, []byte(`"authoritySet":[]`), []byte(`"authoritySet":null`), 1),
		"missing-nested-root":  bytes.Replace(valid, []byte(`"rootDeviceId":"`+f.RootPin.DeviceID+`",`), nil, 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeRecoveryTransitionSubmission(b); e == nil {
				t.Fatal("ambiguous transition schema accepted")
			}
		})
	}
	for name, b := range map[string][]byte{
		"duplicate-device-top":        append([]byte(`{"certificateVersion":"4",`), device[1:]...),
		"duplicate-device-nested":     bytes.Replace(device, []byte(`"recoveryGeneration":"2"`), []byte(`"recoveryGeneration":"2","recoveryGeneration":"2"`), 1),
		"device-null-proof":           bytes.Replace(device, []byte(`"profile":"harmonia/issuer-proof/v2"`), []byte(`"profile":null`), 1),
		"device-missing-wrapper":      bytes.Replace(device, []byte(`"certificateVersion":"4",`), nil, 1),
		"device-missing-empty-parent": bytes.Replace(device, []byte(`"parentHash":"",`), nil, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeRecoveredDeviceSubmission(b); e == nil {
				t.Fatal("ambiguous device schema accepted")
			}
		})
	}
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	advanced, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	if _, e := VerifyAcceptedRecoveryTransition(advanced, f.OldCode); e == nil {
		t.Fatal("accepted transition replayed as new operation")
	}
	bad := f.OldCode
	bad.Sequence++
	if _, e := VerifyAcceptedRecoveryTransition(v, bad); e == nil {
		t.Fatal("acceptance sequence not bound")
	}
	if v.HeadHash() != f.InitializationHash || v.Generation() != "1" {
		t.Fatal("failed or successful validation mutated prior checkpoint")
	}
	s := recoveryClone(t, f.OldCode.Submission)
	s.Transition.OldRecoveryGeneration = "2"
	s.Transition.OldRecoverySigningPublicKey = advanced.SigningPublicKey()
	s.Transition.OldRecoveryReceivingPublicKey = advanced.ReceivingPublicKey()
	s.Transition.NewRecoveryGeneration = "3"
	s.Transition.NewRecoverySigningPublicKey = v.SigningPublicKey()
	s.Transition.NewRecoveryReceivingPublicKey = v.ReceivingPublicKey()
	s.Transition.PreviousTransitionHash = advanced.HeadHash()
	s.Transition.ExpectedSequence = "21"
	oldKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["oldRecovery"]), f.RootPin.AccountID, "1", "1")
	recoveryCheck(t, e)
	s.NewTrustRoot.RecoveryGeneration = "3"
	s.NewTrustRoot.RecoverySigningPublicKey = v.SigningPublicKey()
	s.NewTrustRoot.RecoveryReceivingPublicKey = v.ReceivingPublicKey()
	s.NewTrustRoot, e = SignTrustRoot(f.RootPin.AccountID, "1", s.NewTrustRoot, oldKeys.SigningPrivate)
	recoveryCheck(t, e)
	s.Transition.NewTrustRootHash, e = RecoveryTrustRootReferenceHash(f.RootPin.AccountID, "1", s.NewTrustRoot)
	recoveryCheck(t, e)
	newKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["newRecovery"]), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, e)
	if _, e := SignOldRecoveryTransition(advanced, s, newKeys.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("previous recovery public key was reused")
	}
}
func TestRecoveryAuthorityEveryScalarIsSigned(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	for i := 0; i < reflect.TypeOf(f.OldCode.Submission.Transition).NumField(); i++ {
		name := reflect.TypeOf(f.OldCode.Submission.Transition).Field(i).Name
		t.Run("transition-"+name, func(t *testing.T) {
			r := recoveryClone(t, f.OldCode)
			field := reflect.ValueOf(&r.Submission.Transition).Elem().FieldByName(name)
			field.SetString(field.String() + "x")
			if _, e := VerifyAcceptedRecoveryTransition(v, r); e == nil {
				t.Fatal("changed scalar reused original two signatures")
			}
		})
	}
	advanced, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	for i := 0; i < reflect.TypeOf(f.Device.Submission.Enrollment).NumField(); i++ {
		name := reflect.TypeOf(f.Device.Submission.Enrollment).Field(i).Name
		t.Run("device-"+name, func(t *testing.T) {
			r := recoveryClone(t, f.Device)
			field := reflect.ValueOf(&r.Submission.Enrollment).Elem().FieldByName(name)
			field.SetString(field.String() + "x")
			if _, e := VerifyAcceptedRecoveredDevice(advanced, r); e == nil {
				t.Fatal("changed selection/certificate scalar reused original two signatures")
			}
		})
	}
}
func TestRecoveryAuthorityOriginalInitializationCannotMoveRootOrGenesis(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	for _, name := range []string{"sequence", "root-pair", "initial-grant", "proof-proposal", "device-signature", "recovery-signature"} {
		t.Run(name, func(t *testing.T) {
			o := recoveryClone(t, f.Original)
			switch name {
			case "sequence":
				o.Sequence = 2
			case "root-pair":
				o.Proposal.Device.SigningPublicKey = o.Proposal.RecoverySigningPublicKey
			case "initial-grant":
				o.Proposal.Environments[0].Grant.Grant.EnvironmentID = "fake-initial-Y"
			case "proof-proposal":
				o.Proof.ProposalHash = strings.Repeat("f", 64)
			case "device-signature":
				o.DeviceSignature = o.RecoverySignature
			case "recovery-signature":
				o.RecoverySignature = o.DeviceSignature
			}
			if _, e := VerifyRecoveryInitialization(f.RootPin, o); e == nil {
				t.Fatal("original anchor silently changed")
			}
		})
	}
}

func TestRecoveryAuthorityKnownLegacyKeysAndOperationIDsRemainRetired(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	v, e := VerifyRecoveryInitialization(f.RootPin, f.Original)
	recoveryCheck(t, e)
	current, e := VerifyAcceptedRecoveryTransition(v, f.Reanchor)
	recoveryCheck(t, e)
	s := recoveryClone(t, f.OldCode.Submission)
	s.Transition.OldRecoveryGeneration = current.Generation()
	s.Transition.OldRecoverySigningPublicKey = current.SigningPublicKey()
	s.Transition.OldRecoveryReceivingPublicKey = current.ReceivingPublicKey()
	s.Transition.PreviousTransitionHash = current.HeadHash()
	s.Transition.ExpectedSequence = "22"
	s.Transition.NewRecoveryGeneration = "4"
	s.Transition.NewRecoverySigningPublicKey = f.Reanchor.Submission.Transition.OldRecoverySigningPublicKey
	s.Transition.NewRecoveryReceivingPublicKey = f.Reanchor.Submission.Transition.OldRecoveryReceivingPublicKey
	knownKeys, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["newRecovery"]), f.RootPin.AccountID, "1", "2")
	recoveryCheck(t, e)
	s.NewTrustRoot.RecoveryGeneration = "4"
	s.NewTrustRoot.RecoverySigningPublicKey = s.Transition.NewRecoverySigningPublicKey
	s.NewTrustRoot.RecoveryReceivingPublicKey = s.Transition.NewRecoveryReceivingPublicKey
	s.NewTrustRoot, e = SignTrustRoot(f.RootPin.AccountID, "1", s.NewTrustRoot, knownKeys.SigningPrivate)
	recoveryCheck(t, e)
	s.Transition.NewTrustRootHash, e = RecoveryTrustRootReferenceHash(f.RootPin.AccountID, "1", s.NewTrustRoot)
	recoveryCheck(t, e)
	third, e := DeriveRecoveryKeys(mustHex(t, f.SyntheticSeeds["thirdRecovery"]), f.RootPin.AccountID, "1", "3")
	recoveryCheck(t, e)
	if _, e = SignOldRecoveryTransition(current, s, third.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("accepted legacy public key was recycled into new recovery generation")
	}
	advanced, e := VerifyAcceptedRecoveryTransition(v, f.OldCode)
	recoveryCheck(t, e)
	replay := recoveryClone(t, f.OldCode.Submission)
	replay.Transition.PreviousTransitionHash = advanced.HeadHash()
	if _, e = SignOldRecoveryTransition(advanced, replay, knownKeys.SigningPrivate, time.Unix(f.SyntheticNow, 0)); e == nil {
		t.Fatal("known accepted operation ID was signed again")
	}
	all := recoveryClone(t, f.AllAdmin.Submission)
	all.IssuerEvidence = nil
	data, e := json.Marshal(all)
	recoveryCheck(t, e)
	if _, e = DecodeRecoveryTransitionSubmission(data); e == nil {
		t.Fatal("all Admin submission allowed null proof")
	}
}
