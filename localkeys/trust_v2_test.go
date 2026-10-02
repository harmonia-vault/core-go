package localkeys

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestTrustV2FreezesScopedReceiptAndForbidsManagerExpansion(t *testing.T) {
	cfg := testConfig(t)
	v := openTest(t, cfg)
	trust := trustFixture(t, v)
	trust.CertificateVersion = "2"
	trust.Managers = nil
	trust.EnrollmentCertificate = json.RawMessage(`{"approval":{"certificateVersion":"2","issuerProof":{"synthetic":"storage-only"}}}`)
	if err := v.SaveTrustContext(trust); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	v = openTest(t, cfg)
	restored, err := v.LoadTrustContext()
	if err != nil || restored.CertificateVersion != "2" || len(restored.Managers) != 0 || restored.Accepted {
		t.Fatal("v2 receipt restart lost scope", err)
	}
	for _, field := range []string{"proof", "profile", "version", "managers"} {
		t.Run(field, func(t *testing.T) {
			candidate := trust
			switch field {
			case "proof":
				candidate.EnrollmentCertificate = json.RawMessage(`{"approval":{"certificateVersion":"2","issuerProof":{"synthetic":"replacement"}}}`)
			case "profile":
				candidate.PairingProfile = "directory-tofu"
			case "version":
				candidate.CertificateVersion = "1"
				candidate.Managers = map[string][]byte{"synthetic-manager": trust.SigningPublic}
			case "managers":
				candidate.Managers = map[string][]byte{"synthetic-manager": trust.SigningPublic}
			}
			if err := v.SaveTrustContext(candidate); !errors.Is(err, ErrIdentity) && !errors.Is(err, ErrCorrupt) {
				t.Fatal("bound v2 proof changed", err)
			}
		})
	}
	trust.Accepted = true
	if err := v.SaveTrustContext(trust); err != nil {
		t.Fatal(err)
	}
	trust.Accepted = false
	if err := v.SaveTrustContext(trust); !errors.Is(err, ErrIdentity) {
		t.Fatal("v2 acceptance downgraded")
	}
}
