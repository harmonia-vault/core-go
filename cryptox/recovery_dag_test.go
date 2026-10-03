package cryptox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type recoveryDAGFixture struct {
	SyntheticNow          int64                `json:"syntheticNow"`
	SyntheticSeeds        map[string]string    `json:"syntheticSeedsHex"`
	RootPin               PinnedIssuerRoot     `json:"rootPin"`
	Proof                 IssuerRecoveryDAG    `json:"proof"`
	Approval              EnrollmentApprovalV5 `json:"approval"`
	Creation              EnvironmentChangeV2  `json:"creation"`
	Cipher                SignedMutationWire   `json:"cipher"`
	CanonicalHex          string               `json:"canonicalHex"`
	Hash                  string               `json:"hash"`
	TransitionSigningHex  string               `json:"transitionSigningHex"`
	RecoveredSigningHex   string               `json:"recoveredSigningHex"`
	CertificateSigningHex string               `json:"certificateSigningHex"`
}

func dagBindDependencies(t *testing.T, s *RecoverySource, b RecoveryDependencyBundle) {
	t.Helper()
	hashes, e := sourceReferenceHashes(*s, s.View.InitializationHash)
	recoveryCheck(t, e)
	s.View.Dependencies = []RecoveryDependency{}
	for _, r := range b.Records {
		ref, e := r.Reference()
		recoveryCheck(t, e)
		if hashes[ref.ReferenceHash] {
			s.View.Dependencies = append(s.View.Dependencies, ref)
			delete(hashes, ref.ReferenceHash)
		}
	}
	if len(hashes) != 0 {
		t.Fatal("fixture dependency absent")
	}
	sort.Slice(s.View.Dependencies, func(i, j int) bool {
		if s.View.Dependencies[i].Kind != s.View.Dependencies[j].Kind {
			return s.View.Dependencies[i].Kind < s.View.Dependencies[j].Kind
		}
		return s.View.Dependencies[i].ReferenceHash < s.View.Dependencies[j].ReferenceHash
	})
}
func dagCheck(t *testing.T, stage string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(stage, err)
	}
}
func makeRecoveryDAGFixture(t *testing.T) recoveryDAGFixture {
	t.Helper()
	f := makeIssuerRecoveryFixture(t)
	base := f.Recovery
	now := time.Unix(base.SyntheticNow, 0)
	source, bundle, e := RecoverySourceFromProof3(base.RootPin, f.Proof, 31)
	dagCheck(t, "fixture step 6", e)
	owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	ownerGrant := base.Device.Submission.Grants[0]
	ownerHash, e := IssuerAuthorityHash(ownerGrant)
	dagCheck(t, "fixture step 10", e)
	rec2, e := DeriveRecoveryKeys(bytes.Repeat([]byte{67}, 32), base.RootPin.AccountID, "1", "2")
	dagCheck(t, "fixture step 12", e)
	zkey := bytes.Repeat([]byte{21}, 32)
	newGrant := ownerGrant.Grant
	newGrant.EnvironmentID = "environment-Z"
	newGrant.IdempotencyKey = "recovered-E-create-Z-grant"
	newGrant.Envelope = ""
	packet, e := WrapEnvironmentKey(zkey, EnvelopeContext{AccountID: newGrant.AccountID, AccountGeneration: "1", EnvironmentID: newGrant.EnvironmentID, KeyVersion: "1", RecipientType: "device", RecipientID: newGrant.SubjectDeviceID, RecipientGeneration: "1", RecipientPublicKey: newGrant.SubjectReceivingPublicKey})
	dagCheck(t, "fixture step 19", e)
	newGrant.Envelope = EncodeBase64(packet)
	signedZ, e := SignGrant(newGrant, owner)
	dagCheck(t, "fixture step 22", e)
	zgrant := GrantToWire(signedZ)
	recPacket, e := WrapEnvironmentKey(zkey, EnvelopeContext{AccountID: newGrant.AccountID, AccountGeneration: "1", EnvironmentID: newGrant.EnvironmentID, KeyVersion: "1", RecipientType: "recovery", RecipientID: newGrant.AccountID, RecipientGeneration: "2", RecipientPublicKey: EncodeBase64(rec2.ReceivingPublic)})
	dagCheck(t, "fixture step 25", e)
	context := ValueContext{AccountID: newGrant.AccountID, AccountGeneration: "1", EnvironmentID: newGrant.EnvironmentID, KeyVersion: "1", Name: "SYNTHETIC_REPEATED_RECOVERY"}
	cipher, e := EncryptValue(zkey, context, []byte("synthetic-value-from-recovered-E"))
	dagCheck(t, "fixture step 28", e)
	signedValue, e := SignMutation(Mutation{AccountID: newGrant.AccountID, AccountGeneration: "1", DeviceID: newGrant.SubjectDeviceID, EnvironmentID: newGrant.EnvironmentID, KeyVersion: "1", GrantGeneration: "1", Operation: "put", Name: context.Name, IdempotencyKey: "E-Z-real-cipher", Payload: EncodeBase64(cipher)}, owner)
	dagCheck(t, "fixture step 30", e)
	change, e := SignEnvironmentChange(EnvironmentChange{AccountID: newGrant.AccountID, AccountGeneration: "1", DeviceID: newGrant.SubjectDeviceID, EnvironmentID: newGrant.EnvironmentID, Operation: "create", AuthorityEnvironmentID: ownerGrant.Grant.EnvironmentID, AuthorityKeyVersion: "1", AuthorityGrantGeneration: "1", PreviousKeyVersion: "0", KeyVersion: "1", ExpectedSequence: "32", IdempotencyKey: "recovered-E-create-Z", LabelPayload: EncodeBase64(bytes.Repeat([]byte{24}, 40)), RecoveryGeneration: "2", RecoveryEnvelope: EncodeBase64(recPacket), Grants: []SignedGrantWire{zgrant}, Mutations: []SignedMutationWire{MutationToWire(signedValue)}}, owner)
	dagCheck(t, "fixture step 32", e)
	creation, e := NewEnvironmentChangeV2(change, ownerGrant, nil, owner)
	dagCheck(t, "fixture step 34", e)
	originHash, e := EnvironmentOriginHash(creation.Origin)
	dagCheck(t, "fixture step 36", e)
	source.View.Origins = append(source.View.Origins, creation.Origin)
	source.View.Authorities = append(source.View.Authorities, IssuerRecoveryAuthority{Grant: zgrant, ParentHash: ownerHash, OriginHash: originHash})
	// 恢复来源主路径可为原 root；历史 E/F 只作为精确分支，不升全局权限。
	source.View.IdentityPaths = append(source.View.IdentityPaths, source.View.Path)
	source.View.Path = []IssuerRecoveryArchive{}
	source.View.Targets = []IssuerTarget{}
	manifest := append([]RecoveryEnvironmentVersion(nil), base.OldCode.Submission.EnvironmentManifest...)
	manifest = append(manifest, RecoveryEnvironmentVersion{EnvironmentID: newGrant.EnvironmentID, KeyVersion: "1"})
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].EnvironmentID < manifest[j].EnvironmentID })
	for _, row := range manifest {
		for _, a := range source.View.Authorities {
			g := a.Grant.Grant
			if g.EnvironmentID == row.EnvironmentID && g.KeyVersion == row.KeyVersion && (g.SubjectDeviceID == base.RootPin.DeviceID || g.SubjectDeviceID == newGrant.SubjectDeviceID) {
				h, e := IssuerAuthorityHash(a.Grant)
				dagCheck(t, "fixture step 51", e)
				source.View.Targets = append(source.View.Targets, IssuerTarget{row.EnvironmentID, h})
				break
			}
		}
	}
	if len(source.View.Targets) != 3 {
		t.Fatal("fixture full environment source absent")
	}
	dagBindDependencies(t, &source, bundle)
	current, e := VerifyRecoveryDependencyBundle(base.RootPin, bundle)
	dagCheck(t, "fixture step 62", e)
	if _, e = current.sourceGraph(source, 39); e != nil {
		t.Fatal("created environment source:", e)
	}
	rec3, e := DeriveRecoveryKeys(bytes.Repeat([]byte{68}, 32), base.RootPin.AccountID, "1", "3")
	dagCheck(t, "fixture step 67", e)
	root3 := base.OldCode.Submission.NewTrustRoot
	root3.RecoveryGeneration = "3"
	root3.RecoverySigningPublicKey = EncodeBase64(rec3.SigningPublic)
	root3.RecoveryReceivingPublicKey = EncodeBase64(rec3.ReceivingPublic)
	root3, e = SignTrustRoot(base.RootPin.AccountID, "1", root3, rec3.SigningPrivate)
	dagCheck(t, "fixture step 73", e)
	makeEnvelopes := func(generation string, recipient string) []RecoveryEnvelope {
		out := []RecoveryEnvelope{}
		for _, row := range manifest {
			key := bytes.Repeat([]byte{9}, 32)
			if row.EnvironmentID == "environment-Z" {
				key = zkey
			}
			packet, e := WrapEnvironmentKey(key, EnvelopeContext{AccountID: base.RootPin.AccountID, AccountGeneration: "1", EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, RecipientType: "recovery", RecipientID: base.RootPin.AccountID, RecipientGeneration: generation, RecipientPublicKey: recipient})
			dagCheck(t, "fixture step 82", e)
			out = append(out, RecoveryEnvelope{row.EnvironmentID, row.KeyVersion, EncodeBase64(packet)})
		}
		return out
	}
	old := base.OldCode.Submission.Transition
	old.OperationID = "recovery-second-transition"
	old.ChallengeID = "recovery-second-challenge"
	old.ExpectedSequence = "39"
	old.PreviousTransitionHash = current.current.head
	old.OldRecoveryGeneration = "2"
	old.OldRecoverySigningPublicKey = EncodeBase64(rec2.SigningPublic)
	old.OldRecoveryReceivingPublicKey = EncodeBase64(rec2.ReceivingPublic)
	old.NewRecoveryGeneration = "3"
	old.NewRecoverySigningPublicKey = root3.RecoverySigningPublicKey
	old.NewRecoveryReceivingPublicKey = root3.RecoveryReceivingPublicKey
	second := RecoveryTransitionSubmissionV2{Transition: RecoveryAuthorityTransitionV2(old), EnvironmentManifest: manifest, AuthoritySet: []RecoveryAdminAuthority{}, Envelopes: makeEnvelopes("3", root3.RecoveryReceivingPublicKey), NewTrustRoot: root3}
	second.Transition.EnvironmentManifestHash, e = RecoveryManifestHash(manifest)
	dagCheck(t, "fixture step 100", e)
	second.Transition.EnvelopesHash, e = RecoveryTransitionEnvelopesHash(second.Envelopes)
	dagCheck(t, "fixture step 102", e)
	second.Transition.NewTrustRootHash, e = RecoveryTrustRootReferenceHash(base.RootPin.AccountID, "1", root3)
	dagCheck(t, "fixture step 104", e)
	second.AuthorizationSignature, e = SignOldRecoveryTransitionV2(current, second, rec2.SigningPrivate, now)
	dagCheck(t, "fixture step 106", e)
	second.NewRecoverySignature, e = SignNewRecoveryTransitionV2(current, second, rec3.SigningPrivate, now)
	dagCheck(t, "fixture step 108", e)
	accepted2 := AcceptedRecoveryTransitionV2{second, 40}
	bundle.Records = append(bundle.Records, RecoveryDAGRecord{Kind: "transition-v2", TransitionV2: &accepted2})
	current, e = VerifyRecoveryDependencyBundle(base.RootPin, bundle)
	dagCheck(t, "fixture step 112", e)
	secondHash, e := RecoveryTransitionHashV2(second)
	dagCheck(t, "fixture step 114", e)
	source.View.TrustRoot = root3
	source.View.RecoveryHeadHash = secondHash
	dagBindDependencies(t, &source, bundle)
	// 用户明确为 G 选择三环境 Admin；恢复码授权不会把旧设备自动替成 root。
	gkey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	gx, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{18}, 32))
	dagCheck(t, "fixture step 121", e)
	device := RecoveredDeviceSubmissionV2{CertificateVersion: "5", Capabilities: []string{RecoveryDAGCapability}, Enrollment: RecoveredDeviceEnrollmentV2{AccountID: base.RootPin.AccountID, AccountGeneration: "1", RecoveryGeneration: "3", RecoveryTransitionHash: secondHash, OperationID: "recovery-second-device-G", ChallengeID: "recovery-second-device-challenge", Nonce: EncodeBase64(bytes.Repeat([]byte{80}, 32)), ExpiresAt: "2030000100", RestrictedSessionHash: strings.Repeat("d", 64), ExpectedSequence: "40", DeviceID: "recovered-G", DeviceSigningPublicKey: EncodeBase64(gkey.Public().(ed25519.PublicKey)), DeviceReceivingPublicKey: EncodeBase64(gx.PublicKey().Bytes())}, SelectedRights: []RecoveredDeviceRight{}, Grants: []SignedGrantWire{}, IssuerEvidence: source, Envelopes: []RecoveryEnvelope{}}
	for _, row := range manifest {
		key := bytes.Repeat([]byte{9}, 32)
		if row.EnvironmentID == "environment-Z" {
			key = zkey
		}
		g := ownerGrant.Grant
		g.IssuerDeviceID = "recovered-G"
		g.SubjectDeviceID = "recovered-G"
		g.SubjectSigningPublicKey = device.Enrollment.DeviceSigningPublicKey
		g.SubjectReceivingPublicKey = device.Enrollment.DeviceReceivingPublicKey
		g.EnvironmentID = row.EnvironmentID
		g.KeyVersion = row.KeyVersion
		g.IdempotencyKey = "G-self-" + row.EnvironmentID
		g.Role = "admin"
		g.ExpiresAt = "2030000200"
		packet, e := WrapEnvironmentKey(key, EnvelopeContext{AccountID: g.AccountID, AccountGeneration: "1", EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: "1", RecipientPublicKey: g.SubjectReceivingPublicKey})
		dagCheck(t, "fixture step 139", e)
		g.Envelope = EncodeBase64(packet)
		sig, e := SignGrant(g, gkey)
		dagCheck(t, "fixture step 142", e)
		device.SelectedRights = append(device.SelectedRights, RecoveredDeviceRight{g.EnvironmentID, g.KeyVersion, g.Role, g.ExpiresAt})
		device.Grants = append(device.Grants, GrantToWire(sig))
		device.Envelopes = append(device.Envelopes, RecoveryEnvelope{g.EnvironmentID, g.KeyVersion, g.Envelope})
	}
	device.Enrollment.SelectedRightsHash, e = RecoveredDeviceRightsHash(device.SelectedRights)
	dagCheck(t, "fixture step 148", e)
	device.Enrollment.GrantsHash, e = RecoveredDeviceGrantsHash(device.Grants)
	dagCheck(t, "fixture step 150", e)
	device.Enrollment.EnvelopesHash, e = RecoveredDeviceEnvelopesHash(device.Envelopes)
	dagCheck(t, "fixture step 152", e)
	device.Enrollment.IssuerEvidenceHash, e = source.Hash()
	dagCheck(t, "fixture step 154", e)
	device.RecoverySignature, e = SignRecoveredDeviceByRecoveryV2(current, device, rec3.SigningPrivate, now)
	dagCheck(t, "fixture step 156", e)
	device.DeviceSignature, e = SignRecoveredDeviceAfterHPKEV2(current, device, gkey, gx.Bytes(), now)
	dagCheck(t, "fixture step 158", e)
	acceptedG := AcceptedRecoveredDeviceV2{device, 41}
	bundle.Records = append(bundle.Records, RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &acceptedG})
	current, e = VerifyRecoveryDependencyBundle(base.RootPin, bundle)
	dagCheck(t, "fixture step 162", e)
	ghash, e := RecoveredDeviceReferenceHashV2(device)
	dagCheck(t, "fixture step 164", e)
	source = recoveryClone(t, source)
	source.View.Path = []IssuerRecoveryArchive{{Kind: "recovered", RecoveryEnrollmentHash: ghash}}
	source.View.Targets = []IssuerTarget{}
	for _, g := range device.Grants {
		source.View.Authorities = append(source.View.Authorities, IssuerRecoveryAuthority{Grant: g, RecoveryEnrollmentHash: ghash})
		h, e := IssuerAuthorityHash(g)
		dagCheck(t, "fixture step 171", e)
		source.View.Targets = append(source.View.Targets, IssuerTarget{g.Grant.EnvironmentID, h})
	}
	dagBindDependencies(t, &source, bundle)
	// 第二次恢复设备 G 不持旧码，以完整三环境 Admin 来源签第三次连续轮换。
	rec4, e := DeriveRecoveryKeys(bytes.Repeat([]byte{70}, 32), base.RootPin.AccountID, "1", "4")
	dagCheck(t, "fixture step 177", e)
	root4 := root3
	root4.RecoveryGeneration = "4"
	root4.RecoverySigningPublicKey = EncodeBase64(rec4.SigningPublic)
	root4.RecoveryReceivingPublicKey = EncodeBase64(rec4.ReceivingPublic)
	root4, e = SignTrustRoot(base.RootPin.AccountID, "1", root4, rec4.SigningPrivate)
	dagCheck(t, "fixture step 183", e)
	third := recoveryClone(t, second)
	third.Transition.AuthorizationKind = "all-environments-admin"
	third.Transition.AuthorizerDeviceID = "recovered-G"
	third.Transition.OperationID = "G-all-admin-transition"
	third.Transition.ChallengeID = "G-all-admin-challenge"
	third.Transition.ExpectedSequence = "41"
	third.Transition.PreviousTransitionHash = current.current.head
	third.Transition.OldRecoveryGeneration = "3"
	third.Transition.OldRecoverySigningPublicKey = root3.RecoverySigningPublicKey
	third.Transition.OldRecoveryReceivingPublicKey = root3.RecoveryReceivingPublicKey
	third.Transition.NewRecoveryGeneration = "4"
	third.Transition.NewRecoverySigningPublicKey = root4.RecoverySigningPublicKey
	third.Transition.NewRecoveryReceivingPublicKey = root4.RecoveryReceivingPublicKey
	third.NewTrustRoot = root4
	thirdSource := recoveryClone(t, source)
	third.IssuerEvidence = &thirdSource
	third.AuthoritySet = []RecoveryAdminAuthority{}
	for _, g := range device.Grants {
		h, e := IssuerAuthorityHash(g)
		dagCheck(t, "fixture step 202", e)
		third.AuthoritySet = append(third.AuthoritySet, RecoveryAdminAuthority{EnvironmentID: g.Grant.EnvironmentID, KeyVersion: g.Grant.KeyVersion, GrantGeneration: "1", ExpiresAt: g.Grant.ExpiresAt, AuthorityHash: h})
	}
	third.Transition.AuthoritySetHash, e = RecoveryAdminAuthoritiesHash(third.AuthoritySet)
	dagCheck(t, "fixture step 206", e)
	third.Transition.IssuerEvidenceHash, e = source.Hash()
	dagCheck(t, "fixture step 208", e)
	third.Envelopes = makeEnvelopes("4", root4.RecoveryReceivingPublicKey)
	third.Transition.EnvelopesHash, e = RecoveryTransitionEnvelopesHash(third.Envelopes)
	dagCheck(t, "fixture step 211", e)
	third.Transition.NewTrustRootHash, e = RecoveryTrustRootReferenceHash(base.RootPin.AccountID, "1", root4)
	dagCheck(t, "fixture step 213", e)
	third.AuthorizationSignature, e = SignAllAdminRecoveryTransitionV2(current, third, gkey, now)
	dagCheck(t, "fixture step 215", e)
	third.NewRecoverySignature, e = SignNewRecoveryTransitionV2(current, third, rec4.SigningPrivate, now)
	dagCheck(t, "fixture step 217", e)
	accepted3 := AcceptedRecoveryTransitionV2{third, 42}
	bundle.Records = append(bundle.Records, RecoveryDAGRecord{Kind: "transition-v2", TransitionV2: &accepted3})
	current, e = VerifyRecoveryDependencyBundle(base.RootPin, bundle)
	dagCheck(t, "fixture step 221", e)
	lastHash, e := RecoveryTransitionHashV2(third)
	dagCheck(t, "fixture step 223", e)
	source = recoveryClone(t, source)
	source.View.TrustRoot = root4
	source.View.RecoveryHeadHash = lastHash
	dagBindDependencies(t, &source, bundle)
	proof := IssuerRecoveryDAG{IssuerRecoveryDAGProfile, base.RootPin.AccountID, "1", base.Original, source, bundle.Records}
	verified, e := VerifyIssuerRecoveryDAG(base.RootPin, proof)
	dagCheck(t, "fixture step 230", e)
	recoveryCheck(t, verified.VerifyHistoricalMutationSource(MutationToWire(signedValue), zgrant))
	recoveryCheck(t, verified.VerifyEnvironmentOriginEvent(change, creation.Origin, ownerGrant))
	cb, e := proof.CanonicalBytes()
	dagCheck(t, "fixture step 234", e)
	ph, e := proof.Hash()
	dagCheck(t, "fixture step 236", e)
	tb, e := third.Transition.SigningBytes()
	dagCheck(t, "fixture step 238", e)
	db, e := device.Enrollment.SigningBytes()
	dagCheck(t, "fixture step 240", e)
	approval := makeDAGApproval(t, proof)
	cert, e := approval.Certificate()
	recoveryCheck(t, e)
	certBytes, e := cert.SigningBytes()
	recoveryCheck(t, e)
	return recoveryDAGFixture{SyntheticNow: base.SyntheticNow, SyntheticSeeds: map[string]string{"originalRecovery": strings.Repeat("42", 32), "firstRecovery": strings.Repeat("43", 32), "secondRecovery": strings.Repeat("44", 32), "thirdRecovery": strings.Repeat("46", 32), "EEd": strings.Repeat("06", 32), "EX": strings.Repeat("10", 32), "FEd": strings.Repeat("07", 32), "FX": strings.Repeat("11", 32), "GEd": strings.Repeat("08", 32), "GX": strings.Repeat("12", 32), "HEd": strings.Repeat("0a", 32), "HX": strings.Repeat("14", 32), "ZKey": strings.Repeat("15", 32)}, RootPin: base.RootPin, Proof: proof, Approval: approval, Creation: creation, Cipher: MutationToWire(signedValue), CanonicalHex: hex.EncodeToString(cb), Hash: ph, TransitionSigningHex: hex.EncodeToString(tb), RecoveredSigningHex: hex.EncodeToString(db), CertificateSigningHex: hex.EncodeToString(certBytes)}
}
func TestRecoveryDAGActualRepeatedRecoveryCreatedEnvironmentAndAllAdmin(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	raw, e := json.Marshal(f.Proof)
	recoveryCheck(t, e)
	p, e := DecodeIssuerRecoveryDAG(raw)
	recoveryCheck(t, e)
	v, e := VerifyIssuerRecoveryDAG(f.RootPin, p)
	recoveryCheck(t, e)
	point, e := v.RecoveryCheckpoint()
	recoveryCheck(t, e)
	if point.RecoveryGeneration != "4" || point.AcceptedSequence != 42 || len(p.Records) != 5 {
		t.Fatal("repeated recovery history not retained")
	}
	var g SignedGrantWire
	for _, a := range p.Source.View.Authorities {
		if a.Grant.Grant.SubjectDeviceID == "recovered-G" && a.Grant.Grant.EnvironmentID == "environment-Z" {
			g = a.Grant
		}
	}
	recoveryCheck(t, v.VerifyTarget(g, "recovered-G", g.Grant.SubjectSigningPublicKey, g.Grant.SubjectReceivingPublicKey))
	packet, e := DecodeBase64(g.Grant.Envelope, 80, 80)
	recoveryCheck(t, e)
	key, e := UnwrapEnvironmentKey(bytes.Repeat([]byte{18}, 32), EnvelopeContext{AccountID: g.Grant.AccountID, AccountGeneration: "1", EnvironmentID: g.Grant.EnvironmentID, KeyVersion: "1", RecipientType: "device", RecipientID: "recovered-G", RecipientGeneration: "1", RecipientPublicKey: g.Grant.SubjectReceivingPublicKey}, packet)
	recoveryCheck(t, e)
	defer clear(key)
	cipher, e := DecodeBase64(f.Cipher.Mutation.Payload, 40, MaxValueBytes+40)
	recoveryCheck(t, e)
	plain, e := DecryptValue(key, ValueContext{g.Grant.AccountID, "1", g.Grant.EnvironmentID, "1", f.Cipher.Mutation.Name}, cipher)
	recoveryCheck(t, e)
	defer clear(plain)
	if string(plain) != "synthetic-value-from-recovered-E" {
		t.Fatal("second recovered device did not read real E ciphertext")
	}
	if _, ok := v.VerifiedIdentity("unsigned-directory"); ok {
		t.Fatal("directory added identity")
	}
	if os.Getenv("HARMONIA_WRITE_SYNTHETIC_DAG_VECTOR") == "1" {
		out, e := json.MarshalIndent(f, "", "  ")
		recoveryCheck(t, e)
		out = append(out, '\n')
		if strings.Contains(strings.ToLower(string(out)), "sk-") {
			t.Fatal("synthetic vector accidentally matches credential pattern")
		}
		for _, path := range []string{"testdata/recovery-dag-v1.json", "../../protocol/vectors/recovery-dag-v1.json"} {
			recoveryCheck(t, os.WriteFile(path, out, 0644))
		}
	}
}
func TestRecoveryDAGMissingForwardUnusedAndChangedSourcesFailClosed(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	for _, name := range []string{"missing-record", "wrong-kind", "forward-head", "wrong-init", "wrong-pin", "changed-original", "extra-dependency", "missing-dependency", "own-future-device", "old-domain", "changed-grant", "wrong-sequence"} {
		t.Run(name, func(t *testing.T) {
			p := recoveryClone(t, f.Proof)
			pin := f.RootPin
			switch name {
			case "missing-record":
				p.Records = p.Records[1:]
			case "wrong-kind":
				p.Source.View.Dependencies[0].Kind = "recovered-v2"
			case "forward-head":
				r := p.Records[2].TransitionV2
				p.Records[3].RecoveredV2.Submission.IssuerEvidence.View.RecoveryHeadHash = p.Source.View.RecoveryHeadHash
				_ = r
			case "wrong-init":
				p.Source.View.InitializationHash = strings.Repeat("f", 64)
			case "wrong-pin":
				pin.DeviceID = "server-root"
			case "changed-original":
				p.Initialization.Proposal.Device.ID = "server-root"
			case "extra-dependency":
				p.Source.View.Dependencies = append(p.Source.View.Dependencies, RecoveryDependency{"transition-v1", strings.Repeat("a", 64)})
			case "missing-dependency":
				p.Source.View.Dependencies = p.Source.View.Dependencies[:1]
			case "own-future-device":
				p.Records[3].RecoveredV2.Submission.IssuerEvidence.View.Path = p.Source.View.Path
			case "old-domain":
				p.Records[2].Kind = "transition-v1"
			case "changed-grant":
				p.Source.View.Authorities[len(p.Source.View.Authorities)-1].Grant.Grant.Role = "ro"
			case "wrong-sequence":
				p.Records[3].RecoveredV2.Sequence++
			}
			if _, e := VerifyIssuerRecoveryDAG(pin, p); e == nil {
				t.Fatal("unverified source accepted")
			}
		})
	}
}
func TestRecoveryDAGAllAdminCannotUsePartialSourceOrRootIdentity(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	bundle := RecoveryDependencyBundle{f.Proof.Initialization, f.Proof.Records[:4]}
	d, e := VerifyRecoveryDependencyBundle(f.RootPin, bundle)
	recoveryCheck(t, e)
	g := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	s := f.Proof.Records[4].TransitionV2.Submission
	for _, name := range []string{"partial", "root-identity", "wrong-kv", "wrong-gg", "omit-envelope", "expired"} {
		t.Run(name, func(t *testing.T) {
			x := recoveryClone(t, s)
			switch name {
			case "partial":
				x.AuthoritySet = x.AuthoritySet[:1]
				x.Transition.AuthoritySetHash, _ = RecoveryAdminAuthoritiesHash(x.AuthoritySet)
			case "root-identity":
				x.Transition.AuthorizerDeviceID = f.RootPin.DeviceID
			case "wrong-kv":
				x.AuthoritySet[0].KeyVersion = "1"
				x.Transition.AuthoritySetHash, _ = RecoveryAdminAuthoritiesHash(x.AuthoritySet)
			case "wrong-gg":
				x.AuthoritySet[0].GrantGeneration = "2"
				x.Transition.AuthoritySetHash, _ = RecoveryAdminAuthoritiesHash(x.AuthoritySet)
			case "omit-envelope":
				x.Envelopes = x.Envelopes[:1]
				x.Transition.EnvelopesHash, _ = RecoveryTransitionEnvelopesHash(x.Envelopes)
			}
			testNow := time.Unix(f.SyntheticNow, 0)
			if name == "expired" {
				testNow = time.Unix(2030000201, 0)
				x.Transition.ExpiresAt = "2030000301"
			}
			if _, e := SignAllAdminRecoveryTransitionV2(d, x, g, testNow); e == nil {
				t.Fatal("insufficient current all-environment source signed")
			}
		})
	}
	prior, e := VerifyIssuerRecoveryDAG(f.RootPin, f.Proof)
	recoveryCheck(t, e)
	p := recoveryClone(t, f.Proof)
	p.Source = recoveryClone(t, f.Proof.Records[3].RecoveredV2.Submission.IssuerEvidence)
	p.Records = p.Records[:3]
	if _, e = VerifyIssuerRecoveryDAG(f.RootPin, p); e != nil {
		t.Fatal("valid earlier candidate rejected", e)
	}
	if _, e = VerifyRecoveryDAGAdvance(prior, p); e == nil {
		t.Fatal("known recovery head rolled back")
	}
	if _, e = VerifyRecoveryDAGAdvance(prior, f.Proof); e != nil {
		t.Fatal("same accepted head retry rejected", e)
	}
}
func baseHash(t *testing.T, r RecoveryDAGRecord) string {
	t.Helper()
	ref, e := r.Reference()
	recoveryCheck(t, e)
	return ref.ReferenceHash
}
func TestRecoverySourceStrictTaggedSchemaAndLegacyParser(t *testing.T) {
	f := makeRecoveryDAGFixture(t)
	b, e := json.Marshal(f.Proof)
	recoveryCheck(t, e)
	for _, name := range []string{"duplicate-top", "duplicate-nested", "unknown", "trailing", "utf8", "null-array", "omitted-array", "too-deep"} {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Clone(b)
			switch name {
			case "duplicate-top":
				raw = append([]byte(`{"profile":"harmonia/issuer-proof/v4",`), raw[1:]...)
			case "duplicate-nested":
				raw = bytes.Replace(raw, []byte(`"kind":"proof3"`), []byte(`"kind":"proof3","kind":"proof3"`), 1)
			case "unknown":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "utf8":
				raw = append(raw, 0xff)
			case "null-array":
				var m map[string]json.RawMessage
				recoveryCheck(t, json.Unmarshal(raw, &m))
				m["records"] = json.RawMessage("null")
				raw, e = json.Marshal(m)
				recoveryCheck(t, e)
			case "omitted-array":
				var m map[string]json.RawMessage
				recoveryCheck(t, json.Unmarshal(raw, &m))
				delete(m, "records")
				raw, e = json.Marshal(m)
				recoveryCheck(t, e)
			case "too-deep":
				raw = []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65))
			}
			if _, e := DecodeIssuerRecoveryDAG(raw); e == nil {
				t.Fatal("strict DAG decoder accepted malformed material")
			}
		})
	}
	if _, e = DecodeIssuerRecoveryProof(b); e == nil {
		t.Fatal("old Proof3 parser silently accepted DAG")
	}
	record := f.Proof.Records[4].TransitionV2
	old, e := json.Marshal(record.Submission)
	recoveryCheck(t, e)
	if _, e = DecodeRecoveryTransitionSubmission(old); e == nil {
		t.Fatal("old transition parser silently accepted Source union")
	}
	var c []any
	cb, e := f.Proof.CanonicalBytes()
	recoveryCheck(t, e)
	recoveryCheck(t, json.Unmarshal(cb, &c))
	if len(c) != 6 {
		t.Fatal("wrong Proof4 canonical arity")
	}
	vb, e := f.Proof.Source.View.CanonicalBytes()
	recoveryCheck(t, e)
	recoveryCheck(t, json.Unmarshal(vb, &c))
	if len(c) != 12 {
		t.Fatal("wrong source view arity")
	}
	for _, pair := range [][2]string{{f.TransitionSigningHex, "25"}, {f.RecoveredSigningHex, "18"}, {f.CertificateSigningHex, "16"}} {
		data, e := hex.DecodeString(pair[0])
		recoveryCheck(t, e)
		recoveryCheck(t, json.Unmarshal(data, &c))
		if strconv.Itoa(len(c)) != pair[1] {
			t.Fatal("wrong new domain arity")
		}
	}
}
