package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type recoveryAuthorityFixture struct {
	SyntheticNow int64
	RootPin      PinnedIssuerRoot
	Original     OriginalInitialization
	OldCode      AcceptedRecoveryTransitionV2
	Device       AcceptedRecoveredDeviceV2
	Proof        IssuerRecoveryDAG
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
	p := recoveryClone(t, f.Approval.IssuerProof)
	now := time.Unix(f.SyntheticNow, 0)
	pin := originPin(f)
	o := p.Initialization
	root := p.Source.View.TrustRoot
	initial := o.Proposal.Environments[0].Grant
	oldKeys, e := DeriveRecoveryKeys(bytes.Repeat([]byte{66}, 32), pin.AccountID, "1", "1")
	recoveryCheck(t, e)
	newKeys, e := DeriveRecoveryKeys(bytes.Repeat([]byte{67}, 32), pin.AccountID, "1", "2")
	recoveryCheck(t, e)
	bundle := RecoveryDependencyBundle{Initialization: o, Records: []RecoveryDAGRecord{}}
	v, e := VerifyRecoveryDependencyBundle(pin, bundle)
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
	s := RecoveryTransitionSubmissionV2{Transition: RecoveryAuthorityTransitionV2{AccountID: pin.AccountID, AccountGeneration: "1", OperationID: "transition-old", ChallengeID: "transition-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{71}, 32)), ExpiresAt: "2030000100", SessionHash: strings.Repeat("a", 64), ExpectedSequence: "20", PreviousTransitionHash: v.current.HeadHash(), OldRecoveryGeneration: "1", OldRecoverySigningPublicKey: root.RecoverySigningPublicKey, OldRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, NewRecoveryGeneration: "2", NewRecoverySigningPublicKey: newRoot.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: newRoot.RecoveryReceivingPublicKey, AuthorizationKind: "old-recovery", EnvironmentManifestHash: mh, EnvelopesHash: eh, NewTrustRootHash: rh}, EnvironmentManifest: manifest, AuthoritySet: []RecoveryAdminAuthority{}, Envelopes: envelopes, NewTrustRoot: newRoot}
	s.AuthorizationSignature, e = SignOldRecoveryTransitionV2(v, s, oldKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	s.NewRecoverySignature, e = SignNewRecoveryTransitionV2(v, s, newKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	oldRecord := AcceptedRecoveryTransitionV2{Submission: s, Sequence: 21}
	bundle.Records = append(bundle.Records, RecoveryDAGRecord{Kind: "transition-v2", TransitionV2: &oldRecord})
	advanced, e := VerifyRecoveryDependencyBundle(pin, bundle)
	recoveryCheck(t, e)
	p.Source.View.Targets = []IssuerTarget{}
	for _, a := range p.Source.View.Authorities {
		g := a.Grant.Grant
		if g.SubjectDeviceID == "device-B" && ((g.EnvironmentID == "env-fixture" && g.KeyVersion == "2") || g.EnvironmentID == "environment-Y") {
			h, e := IssuerAuthorityHash(a.Grant)
			recoveryCheck(t, e)
			p.Source.View.Targets = append(p.Source.View.Targets, IssuerTarget{g.EnvironmentID, h})
		}
	}
	p.Source.View.TrustRoot = newRoot
	p.Source.View.RecoveryHeadHash = advanced.current.HeadHash()
	dagBindDependencies(t, &p.Source, bundle)
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
	deviceProof.Source.View.TrustRoot = newRoot
	ds := RecoveredDeviceSubmissionV2{CertificateVersion: "5", Capabilities: []string{RecoveryDAGCapability}, Enrollment: RecoveredDeviceEnrollmentV2{AccountID: pin.AccountID, AccountGeneration: "1", RecoveryGeneration: "2", RecoveryTransitionHash: advanced.current.HeadHash(), OperationID: "recover-device-E", ChallengeID: "recover-device-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{73}, 32)), ExpiresAt: "2030000100", RestrictedSessionHash: strings.Repeat("c", 64), ExpectedSequence: "30", DeviceID: "recovered-E", DeviceSigningPublicKey: devicePub, DeviceReceivingPublicKey: receivingPub}, SelectedRights: []RecoveredDeviceRight{{EnvironmentID: "environment-Y", KeyVersion: "1", Role: "admin", ExpiresAt: "0"}}, Grants: []SignedGrantWire{GrantToWire(g)}, IssuerEvidence: deviceProof.Source, Envelopes: []RecoveryEnvelope{{EnvironmentID: "environment-Y", KeyVersion: "1", Envelope: g.Grant.Envelope}}}
	ds.Enrollment.SelectedRightsHash, e = RecoveredDeviceRightsHash(ds.SelectedRights)
	recoveryCheck(t, e)
	ds.Enrollment.GrantsHash, e = RecoveredDeviceGrantsHash(ds.Grants)
	recoveryCheck(t, e)
	ds.Enrollment.EnvelopesHash, e = RecoveredDeviceEnvelopesHash(ds.Envelopes)
	recoveryCheck(t, e)
	ds.Enrollment.IssuerEvidenceHash, e = ds.IssuerEvidence.Hash()
	recoveryCheck(t, e)
	ds.RecoverySignature, e = SignRecoveredDeviceByRecoveryV2(advanced, ds, newKeys.SigningPrivate, now)
	recoveryCheck(t, e)
	ds.DeviceSignature, e = SignRecoveredDeviceAfterHPKEV2(advanced, ds, deviceKey, receiving.Bytes(), now)
	recoveryCheck(t, e)
	deviceRecord := AcceptedRecoveredDeviceV2{Submission: ds, Sequence: 31}
	bundle.Records = append(bundle.Records, RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &deviceRecord})
	_, e = VerifyRecoveryDependencyBundle(pin, bundle)
	recoveryCheck(t, e)

	p.Records = bundle.Records
	return recoveryAuthorityFixture{SyntheticNow: f.SyntheticNow, RootPin: pin, Original: o, OldCode: oldRecord, Device: deviceRecord, Proof: p}
}
