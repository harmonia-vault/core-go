package localkeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestTrustV4ProtectedReceiptNoManagersAndNoVersionMigration(t *testing.T) {
	config := testConfig(t)
	v := openTest(t, config)
	trust := trustFixture(t, v)
	trust.CertificateVersion = "4"
	trust.Managers = nil
	if e := v.SaveTrustContext(trust); e != nil {
		t.Fatal(e)
	}
	if e := v.Close(); e != nil {
		t.Fatal(e)
	}
	v = openTest(t, config)
	saved, e := v.LoadTrustContext()
	if e != nil || saved.CertificateVersion != "4" || saved.Accepted || len(saved.Managers) != 0 {
		t.Fatal("v4 pending receipt lost binding", e)
	}
	trust.Accepted = true
	if e = v.SaveTrustContext(trust); e != nil {
		t.Fatal(e)
	}
	for _, version := range []string{"2", "3"} {
		bad := trust
		bad.CertificateVersion = version
		if e = v.SaveTrustContext(bad); !errors.Is(e, ErrIdentity) {
			t.Fatal("v4 original version silently migrated", e)
		}
	}
	bad := trust
	bad.Managers = map[string][]byte{"directory-manager": bytes.Repeat([]byte{66}, 32)}
	if e = v.SaveTrustContext(bad); !errors.Is(e, ErrCorrupt) {
		t.Fatal("v4 global manager directory accepted", e)
	}
	bad = trust
	bad.EnrollmentCertificate = json.RawMessage(`{"x":"` + string(bytes.Repeat([]byte{'x'}, maxEnrollmentCertificateV4)) + `"}`)
	if e = v.SaveTrustContext(bad); !errors.Is(e, ErrCorrupt) {
		t.Fatal("oversized v4 original receipt accepted", e)
	}
	// 本包只保存结构绑定，密码学证书由syncclient在保存前和daemon重启时验证。
	trust.Accepted = false
	if e = v.SaveTrustContext(trust); !errors.Is(e, ErrIdentity) {
		t.Fatal("accepted v4 receipt downgraded", e)
	}
}
