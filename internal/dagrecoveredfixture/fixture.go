// Package dagrecoveredfixture supplies public synthetic cryptographic test vectors.
// Production code must not import it. No account, credential or platform auth is used.
package dagrecoveredfixture

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"os"
	"testing"
	"time"
)

type Fixture struct {
	Pin        cryptox.PinnedIssuerRoot
	Prior      cryptox.AcceptedRecoveryTransitionV2
	Bundle     cryptox.RecoveryDependencyBundle
	Submission cryptox.RecoveredDeviceSubmissionV2
}

func Load(t testing.TB, path, deviceID string, signing ed25519.PrivateKey, receiving []byte) Fixture {
	t.Helper()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal("public synthetic signed fixture", e)
		}
	}
	raw, e := os.ReadFile(path)
	must(e)
	var wire struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	must(json.Unmarshal(raw, &wire))
	f := Fixture{Pin: wire.Pin, Prior: *wire.Proof.Records[2].TransitionV2, Bundle: cryptox.RecoveryDependencyBundle{Initialization: wire.Proof.Initialization, Records: wire.Proof.Records[:3]}, Submission: wire.Proof.Records[3].RecoveredV2.Submission}
	// Keep the proven previous transition and bind the new packet to that same session.
	f.Submission.Enrollment.RestrictedSessionHash = f.Prior.Submission.Transition.SessionHash
	if signing == nil {
		signing = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
		defer clear(signing)
	}
	if receiving == nil {
		receiving = bytes.Repeat([]byte{18}, 32)
		defer clear(receiving)
	}
	if deviceID == "" {
		deviceID = f.Submission.Enrollment.DeviceID
	}
	old := f.Submission.Enrollment
	x, e := ecdh.X25519().NewPrivateKey(receiving)
	must(e)
	f.Submission.Enrollment.DeviceID = deviceID
	f.Submission.Enrollment.DeviceSigningPublicKey = cryptox.EncodeBase64(signing.Public().(ed25519.PublicKey))
	f.Submission.Enrollment.DeviceReceivingPublicKey = cryptox.EncodeBase64(x.PublicKey().Bytes())
	oldX := bytes.Repeat([]byte{18}, 32)
	defer clear(oldX)
	for i, signed := range f.Submission.Grants {
		g := signed.Grant
		context := cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: old.DeviceID, RecipientGeneration: "1", RecipientPublicKey: old.DeviceReceivingPublicKey}
		packet, e := cryptox.DecodeBase64(g.Envelope, 1, 1<<20)
		must(e)
		key, e := cryptox.UnwrapEnvironmentKey(oldX, context, packet)
		must(e)
		context.RecipientID = deviceID
		context.RecipientPublicKey = f.Submission.Enrollment.DeviceReceivingPublicKey
		packet, e = cryptox.WrapEnvironmentKey(key, context)
		clear(key)
		must(e)
		g.IssuerDeviceID = deviceID
		g.SubjectDeviceID = deviceID
		g.SubjectSigningPublicKey = f.Submission.Enrollment.DeviceSigningPublicKey
		g.SubjectReceivingPublicKey = context.RecipientPublicKey
		g.Envelope = cryptox.EncodeBase64(packet)
		s, e := cryptox.SignGrant(g, signing)
		must(e)
		f.Submission.Grants[i] = cryptox.GrantToWire(s)
		f.Submission.Envelopes[i].Envelope = g.Envelope
	}
	f.Submission.Enrollment.GrantsHash, e = cryptox.RecoveredDeviceGrantsHash(f.Submission.Grants)
	must(e)
	f.Submission.Enrollment.EnvelopesHash, e = cryptox.RecoveredDeviceEnvelopesHash(f.Submission.Envelopes)
	must(e)
	graph, e := cryptox.VerifyRecoveryDependencyBundle(f.Pin, f.Bundle)
	must(e)
	seed := bytes.Repeat([]byte{68}, 32)
	defer clear(seed)
	keys, e := cryptox.DeriveRecoveryKeys(seed, f.Pin.AccountID, f.Pin.AccountGeneration, "3")
	must(e)
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	now := time.Unix(2030000000, 0)
	f.Submission.RecoverySignature, e = cryptox.SignRecoveredDeviceByRecoveryV2(graph, f.Submission, keys.SigningPrivate, now)
	must(e)
	f.Submission.DeviceSignature, e = cryptox.SignRecoveredDeviceAfterHPKEV2(graph, f.Submission, signing, receiving, now)
	must(e)
	return f
}
