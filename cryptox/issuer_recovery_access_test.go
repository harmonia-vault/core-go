package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestRecoveryReaderVerifiesActualCipherAndCannotWriteWithROKey(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	v, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, f.Proof)
	recoveryCheck(t, e)
	recovered := f.Recovery.Device.Submission.Grants[0]
	child := f.Proof.Path[1].Enrollment.Approval.Grants[0]
	identity, known := v.VerifiedIdentity(recovered.Grant.SubjectDeviceID)
	if !known || identity.SigningPublicKey != recovered.Grant.SubjectSigningPublicKey || identity.ReceivingPublicKey != recovered.Grant.SubjectReceivingPublicKey {
		t.Fatal("recovered issuer identity not bound")
	}
	if _, known = v.VerifiedIdentity("unsigned-server-directory"); known {
		t.Fatal("directory identity became trusted")
	}
	key := bytes.Repeat([]byte{9}, 32)
	g := recovered.Grant
	context := ValueContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, Name: "SYNTHETIC_RECOVERED_VALUE"}
	packet, e := EncryptValue(key, context, []byte("synthetic-only-recovered-source"))
	recoveryCheck(t, e)
	mutation := Mutation{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, DeviceID: g.SubjectDeviceID, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, GrantGeneration: g.GrantGeneration, Operation: "put", IdempotencyKey: "recovered-signed-put", Name: context.Name, Payload: EncodeBase64(packet)}
	writer := ed25519.NewKeyFromSeed(mustHex(t, f.Recovery.SyntheticSeeds["deviceEd"]))
	signed, e := SignMutation(mutation, writer)
	recoveryCheck(t, e)
	recoveryCheck(t, v.VerifyHistoricalMutationSource(MutationToWire(signed), recovered))
	envelope, e := DecodeBase64(child.Grant.Envelope, 80, 80)
	recoveryCheck(t, e)
	readKey, e := UnwrapEnvironmentKey(bytes.Repeat([]byte{17}, 32), EnvelopeContext{AccountID: child.Grant.AccountID, AccountGeneration: child.Grant.AccountGeneration, EnvironmentID: child.Grant.EnvironmentID, KeyVersion: child.Grant.KeyVersion, RecipientType: "device", RecipientID: child.Grant.SubjectDeviceID, RecipientGeneration: child.Grant.GrantGeneration, RecipientPublicKey: child.Grant.SubjectReceivingPublicKey}, envelope)
	recoveryCheck(t, e)
	defer clear(readKey)
	plaintext, e := DecryptValue(readKey, context, packet)
	recoveryCheck(t, e)
	defer clear(plaintext)
	if string(plaintext) != "synthetic-only-recovered-source" {
		t.Fatal("reader did not recover actual ciphertext")
	}
	mutation.DeviceID = child.Grant.SubjectDeviceID
	mutation.IdempotencyKey = "ro-forged-valid-cipher"
	mutation.GrantGeneration = child.Grant.GrantGeneration
	rogue, e := SignMutation(mutation, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	recoveryCheck(t, e)
	if v.VerifyHistoricalMutationSource(MutationToWire(rogue), child) == nil {
		t.Fatal("RO device symmetric key became write authority")
	}
	for _, name := range []string{"writer", "environment", "key-version", "grant-generation"} {
		t.Run(name, func(t *testing.T) {
			m := signed.Mutation
			switch name {
			case "writer":
				m.DeviceID = "unsigned-device"
			case "environment":
				m.EnvironmentID = "unselected-X"
			case "key-version":
				m.KeyVersion = "2"
			case "grant-generation":
				m.GrantGeneration = "2"
			}
			s, e := SignMutation(m, writer)
			recoveryCheck(t, e)
			if v.VerifyHistoricalMutationSource(MutationToWire(s), recovered) == nil {
				t.Fatal("mutation was detached from exact writable authority")
			}
		})
	}
}
func TestRecoveryReaderMatchesActualEnvironmentOriginEvent(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	v, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, f.Proof)
	recoveryCheck(t, e)
	origin := makeOriginFixture(t)
	s := origin.Rotation
	authority, known := v.Authority(s.Origin.Origin.AuthorityHash)
	if !known {
		t.Fatal("actor's frozen Admin source missing")
	}
	change := SignedEnvironmentChange{Change: s.Change, Signature: s.Signature}
	recoveryCheck(t, v.VerifyEnvironmentOriginEvent(change, s.Origin, authority))
	changed := change
	changed.Change = recoveryClone(t, change.Change)
	changed.Change.RecoveryEnvelope = EncodeBase64(bytes.Repeat([]byte{6}, 80))
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	changed, e = SignEnvironmentChange(changed.Change, manager)
	recoveryCheck(t, e)
	if v.VerifyEnvironmentOriginEvent(changed, s.Origin, authority) == nil {
		t.Fatal("valid outer manager signature bypassed frozen data/control reference")
	}
}
func TestRecoveryCheckpointRejectsOtherwiseValidOlderRecoveryGraph(t *testing.T) {
	f := makeIssuerRecoveryFixture(t)
	known, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, f.Proof)
	recoveryCheck(t, e)
	next, e := VerifyRecoveryCheckpointAdvance(known, f.Proof)
	recoveryCheck(t, e)
	point, e := next.RecoveryCheckpoint()
	recoveryCheck(t, e)
	if point.TransitionHead != f.Recovery.TransitionHash || point.RecoveryGeneration != "2" || point.AcceptedSequence != 21 {
		t.Fatal("checkpoint did not bind accepted recovery head")
	}
	p := f.Recovery.Device.Submission.IssuerEvidence
	o := f.Recovery.Original.Proposal
	old := IssuerRecoveryProof{Profile: IssuerRecoveryProfile, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, TrustRoot: TrustRoot{o.Device.ID, o.Device.SigningPublicKey, o.Device.ReceivingPublicKey, o.RecoveryGeneration, o.RecoverySigningPublicKey, o.RecoveryReceivingPublicKey, o.TrustRootSignature}, Initialization: f.Recovery.Original, Path: pairedRecoveryPath(p.Path), Authorities: []IssuerRecoveryAuthority{}, Targets: p.Targets, Origins: p.Origins, IdentityPaths: [][]IssuerRecoveryArchive{}, Transitions: []AcceptedRecoveryTransition{}, RecoveredDevices: []AcceptedRecoveredDevice{}}
	for _, a := range p.Authorities {
		old.Authorities = append(old.Authorities, IssuerRecoveryAuthority{Grant: a.Grant, ParentHash: a.ParentHash, OriginHash: a.OriginHash, PreviousGrantHash: a.PreviousGrantHash})
	}
	for _, path := range p.IdentityPaths {
		old.IdentityPaths = append(old.IdentityPaths, pairedRecoveryPath(path))
	}
	if _, e := VerifyIssuerRecoveryEvidence(f.Recovery.RootPin, old); e != nil {
		t.Fatal("regression candidate is not a valid older graph")
	}
	if _, e := VerifyRecoveryCheckpointAdvance(known, old); e == nil {
		t.Fatal("valid historical graph rolled back an already seen recovery head")
	}
}

func TestRecoveredDeviceBuilderBootSourceIsExplicitAndIndependent(t *testing.T) {
	f := makeRecoveryAuthorityFixture(t)
	proof, e := BuildRecoveredDeviceIssuerEvidence(f.RootPin, f.Original, []AcceptedRecoveryTransition{f.OldCode}, f.Device)
	recoveryCheck(t, e)
	v, e := VerifyIssuerRecoveryEvidence(f.RootPin, proof)
	recoveryCheck(t, e)
	g := f.Device.Submission.Grants[0]
	recoveryCheck(t, v.VerifyTarget(g, g.Grant.SubjectDeviceID, g.Grant.SubjectSigningPublicKey, g.Grant.SubjectReceivingPublicKey))
	if len(proof.Path) != 1 || proof.Path[0].Kind != "recovered" || len(proof.Targets) != 1 || proof.Targets[0].EnvironmentID != "environment-Y" {
		t.Fatal("builder silently expanded selected device scope")
	}
	pin := f.RootPin
	pin.SigningPublicKey = g.Grant.SubjectSigningPublicKey
	if _, e := BuildRecoveredDeviceIssuerEvidence(pin, f.Original, []AcceptedRecoveryTransition{f.OldCode}, f.Device); e == nil {
		t.Fatal("new recovered device replaced original protected root pin")
	}
	changed := recoveryClone(t, f.Device)
	changed.Sequence++
	if _, e := BuildRecoveredDeviceIssuerEvidence(f.RootPin, f.Original, []AcceptedRecoveryTransition{f.OldCode}, changed); e == nil {
		t.Fatal("receipt sequence was inferred from server metadata")
	}
	if _, e := BuildRecoveredDeviceIssuerEvidence(f.RootPin, f.Original, []AcceptedRecoveryTransition{}, f.Device); e == nil {
		t.Fatal("builder trusted current recovery pub without transitions")
	}
	f.Device.Submission.Grants[0].Grant.Role = "ro"
	if proof.RecoveredDevices[0].Submission.Grants[0].Grant.Role != "admin" {
		t.Fatal("returned proof borrowed mutable input journal")
	}
}
