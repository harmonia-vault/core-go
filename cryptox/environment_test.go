package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEnvironmentLifecycleCrossLanguageVector(t *testing.T) {
	var v struct {
		SyntheticSigningSeedHex string `json:"syntheticSigningSeedHex"`
		SigningPublicKey        string `json:"signingPublicKey"`
		Changes                 []struct {
			Signed        SignedEnvironmentChange `json:"signed"`
			PayloadBase64 string                  `json:"payloadBase64"`
			GrantsHash    string                  `json:"grantsHash"`
			MutationsHash string                  `json:"mutationsHash"`
		} `json:"changes"`
		Revocation struct {
			Signed          SignedDeviceRevocation `json:"signed"`
			PayloadBase64   string                 `json:"payloadBase64"`
			AuthoritiesHash string                 `json:"authoritiesHash"`
		} `json:"revocation"`
	}
	b, e := os.ReadFile("testdata/environment-lifecycle-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	pub, e := DecodeBase64(v.SigningPublicKey, 32, 32)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := hex.DecodeString(v.SyntheticSigningSeedHex)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	for _, item := range v.Changes {
		t.Run(item.Signed.Change.Operation, func(t *testing.T) {
			payload, e := item.Signed.Change.SigningBytes()
			if e != nil || EncodeBase64(payload) != item.PayloadBase64 {
				t.Fatalf("canonical payload: %v", e)
			}
			gh, e := EnvironmentGrantsHash(item.Signed.Change.Grants)
			if e != nil || gh != item.GrantsHash {
				t.Fatalf("grant manifest: %v", e)
			}
			mh, e := EnvironmentMutationsHash(item.Signed.Change.Mutations)
			if e != nil || mh != item.MutationsHash {
				t.Fatalf("mutation manifest: %v", e)
			}
			if e := VerifyEnvironmentChange(item.Signed, pub); e != nil {
				t.Fatal(e)
			}
			signed, e := SignEnvironmentChange(item.Signed.Change, key)
			if e != nil || signed.Signature != item.Signed.Signature {
				t.Fatalf("signature: %v", e)
			}
			changed := item.Signed
			changed.Change.ExpectedSequence = "9"
			if VerifyEnvironmentChange(changed, pub) == nil {
				t.Fatal("checkpoint substitution accepted")
			}
		})
	}
	r := v.Revocation
	payload, e := r.Signed.Revocation.SigningBytes()
	if e != nil || EncodeBase64(payload) != r.PayloadBase64 {
		t.Fatalf("revocation payload: %v", e)
	}
	ah, e := RevocationAuthorityHash(r.Signed.Revocation.Authorities)
	if e != nil || ah != r.AuthoritiesHash {
		t.Fatalf("authority manifest: %v", e)
	}
	if e := VerifyDeviceRevocation(r.Signed, pub); e != nil {
		t.Fatal(e)
	}
	signed, e := SignDeviceRevocation(r.Signed.Revocation, key)
	if e != nil || signed.Signature != r.Signed.Signature {
		t.Fatalf("revocation signature: %v", e)
	}
	changed := r.Signed
	changed.Revocation.Nonce = EncodeBase64(bytes.Repeat([]byte{99}, 32))
	if VerifyDeviceRevocation(changed, pub) == nil {
		t.Fatal("revocation nonce substitution accepted")
	}
}
func TestEnvironmentLabelUsesIndependentAEADDomain(t *testing.T) {
	key := bytes.Repeat([]byte{51}, 32)
	ctx := EnvironmentLabelContext{"synthetic-account", "1", "synthetic-env", "1"}
	plain := []byte("测试环境")
	packet, e := EncryptEnvironmentLabel(key, ctx, plain)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := DecryptEnvironmentLabel(key, ctx, packet)
	if e != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("label round trip: %v", e)
	}
	changed := ctx
	changed.KeyVersion = "2"
	if _, e := DecryptEnvironmentLabel(key, changed, packet); e == nil {
		t.Fatal("old version label accepted")
	}
	if _, e := DecryptValue(key, ValueContext{ctx.AccountID, ctx.AccountGeneration, ctx.EnvironmentID, ctx.KeyVersion, "HARMONIA_ENVIRONMENT_LABEL"}, packet); e == nil {
		t.Fatal("label accepted as variable")
	}
	packet[len(packet)-1] ^= 1
	if _, e := DecryptEnvironmentLabel(key, ctx, packet); e == nil {
		t.Fatal("tampered label accepted")
	}
	if _, e := EncryptEnvironmentLabel(key, ctx, bytes.Repeat([]byte{1}, MaxValueBytes+1)); e == nil {
		t.Fatal("oversized label accepted")
	}
}
func TestEnvironmentWireEmptyManifestsAndCanonicalLimits(t *testing.T) {
	c := EnvironmentChange{AccountID: "synthetic-account", AccountGeneration: "1", DeviceID: "admin", EnvironmentID: "dev", Operation: "delete", AuthorityEnvironmentID: "dev", AuthorityKeyVersion: "1", AuthorityGrantGeneration: "1", PreviousKeyVersion: "1", KeyVersion: "1", ExpectedSequence: "0", IdempotencyKey: "delete-dev", RecoveryGeneration: "1"}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), `"grants":[]`) || !strings.Contains(string(b), `"mutations":[]`) {
		t.Fatal("nil manifest encoded as null")
	}
	if _, e := c.SigningBytes(); e != nil {
		t.Fatal(e)
	}
	for _, checkpoint := range []string{"01", "9007199254740992", "18446744073709551616"} {
		c.ExpectedSequence = checkpoint
		if _, e := c.SigningBytes(); e == nil {
			t.Fatalf("invalid checkpoint %q accepted", checkpoint)
		}
	}
}
