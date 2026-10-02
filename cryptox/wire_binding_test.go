package cryptox

import (
	"bytes"
	"errors"
	"testing"
)

// 使用仍符合格式的替换值，区分真正签名绑定与输入格式拒绝。
func TestValidSubstitutionsFailSignature(t *testing.T) {
	v := readVectors(t)
	pub, err := DecodeBase64(v.SigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Mutation){
		func(m *Mutation) { m.AccountID = "other-account" },
		func(m *Mutation) { m.AccountGeneration = "2" },
		func(m *Mutation) { m.DeviceID = "other-device" },
		func(m *Mutation) { m.EnvironmentID = "other-environment" },
		func(m *Mutation) { m.KeyVersion = "2" },
		func(m *Mutation) { m.GrantGeneration = "2" },
		func(m *Mutation) { m.Operation = "delete"; m.Payload = "" },
		func(m *Mutation) { m.IdempotencyKey = "other-mutation" },
		func(m *Mutation) { m.Name = "OTHER_NAME" },
		func(m *Mutation) {
			b, _ := DecodeBase64(m.Payload, 40, MaxValueBytes+40)
			b[len(b)-1] ^= 1
			m.Payload = EncodeBase64(b)
		},
	}
	for i, change := range mutations {
		bad := v.Mutation
		change(&bad.Mutation)
		if _, err := bad.Mutation.SigningBytes(); err != nil {
			t.Fatalf("fixture %d became noncanonical: %v", i, err)
		}
		if err := VerifyMutation(bad, pub); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("substitution %d signature result %v", i, err)
		}
	}
	grants := []func(*Grant){
		func(g *Grant) { g.AccountID = "other-account" }, func(g *Grant) { g.AccountGeneration = "2" },
		func(g *Grant) { g.IssuerDeviceID = "other-issuer" }, func(g *Grant) { g.SubjectDeviceID = "other-subject" },
		func(g *Grant) { g.SubjectSigningPublicKey = EncodeBase64(bytes.Repeat([]byte{4}, 32)) },
		func(g *Grant) { g.SubjectReceivingPublicKey = EncodeBase64(bytes.Repeat([]byte{5}, 32)) },
		func(g *Grant) { g.EnvironmentID = "other-environment" }, func(g *Grant) { g.KeyVersion = "2" },
		func(g *Grant) { g.GrantGeneration = "2" }, func(g *Grant) { g.Role = "ro" },
		func(g *Grant) { g.ExpiresAt = "2000000000" }, func(g *Grant) { g.IdempotencyKey = "other-grant" },
		func(g *Grant) {
			b, _ := DecodeBase64(g.Envelope, 80, 80)
			b[len(b)-1] ^= 1
			g.Envelope = EncodeBase64(b)
		},
	}
	for i, change := range grants {
		bad := v.Grant
		change(&bad.Grant)
		if _, err := bad.Grant.SigningBytes(); err != nil {
			t.Fatalf("grant fixture %d became noncanonical: %v", i, err)
		}
		if err := VerifyGrant(bad, pub); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("grant substitution %d signature result %v", i, err)
		}
	}
}
