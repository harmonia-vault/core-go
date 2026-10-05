package localkeys

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestTrustV5ProtectedReceiptNoManagersAndNoVersionMigration(t *testing.T) {
	config := testConfig(t)
	v := openTest(t, config)
	trust := trustFixture(t, v)
	trust.CertificateVersion = "5"
	if e := v.SaveTrustContext(trust); e != nil {
		t.Fatal(e)
	}
	if e := v.Close(); e != nil {
		t.Fatal(e)
	}
	v = openTest(t, config)
	saved, e := v.LoadTrustContext()
	if e != nil || saved.CertificateVersion != "5" || saved.Accepted {
		t.Fatal("v5 pending receipt lost binding", e)
	}
	trust.Accepted = true
	if e = v.SaveTrustContext(trust); e != nil {
		t.Fatal(e)
	}
	for _, version := range []string{"1", "2", "3", "4"} {
		bad := trust
		bad.CertificateVersion = version
		if e = v.SaveTrustContext(bad); !errors.Is(e, ErrCorrupt) {
			t.Fatal("old receipt accepted", version, e)
		}
	}
	raw, _ := json.Marshal(trust)
	var fields map[string]any
	if e = json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	fields["managers"] = map[string]string{"directory-manager": "untrusted"}
	raw, _ = json.Marshal(fields)
	if e = v.Save("trust-v1", raw); e != nil {
		t.Fatal(e)
	}
	if _, e = v.LoadTrustContext(); !errors.Is(e, ErrCorrupt) {
		t.Fatal("old directory loaded", e)
	}
	raw, _ = json.Marshal(trust)
	if e = v.Save("trust-v1", raw); e != nil {
		t.Fatal(e)
	}
	bad := trust
	bad.EnrollmentCertificate = json.RawMessage(`{"x":"` + string(bytes.Repeat([]byte{'x'}, maxEnrollmentCertificateV5)) + `"}`)
	if e = v.SaveTrustContext(bad); !errors.Is(e, ErrCorrupt) {
		t.Fatal("oversized v5 original receipt accepted", e)
	}
	// 本包只保存结构绑定，密码学证书由syncclient在保存前和daemon重启时验证。
	trust.Accepted = false
	if e = v.SaveTrustContext(trust); !errors.Is(e, ErrIdentity) {
		t.Fatal("accepted v5 receipt downgraded", e)
	}
}
