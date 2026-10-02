package cryptox

import (
	"strings"
	"testing"
)

func TestStrictJSONBoundedScanner(t *testing.T) {
	for _, data := range []string{`{}`, `[]`, `{"a":1,"b":[{"a":"x"},true,null]}`, `{"a":"text containing { [ ] }"}`} {
		if e := ValidateStrictJSON([]byte(data), 1024); e != nil {
			t.Fatal("合法JSON拒绝", e)
		}
	}
	for name, data := range map[string]string{"samekey": `{"a":1,"a":2}`, "nested": `{"b":{"a":1,"a":2}}`, "escaped": `{"a":1,"\u0061":2}`, "trailing": `{}[]`, "broken": `{"a":`, "depth": strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), "utf8": string([]byte{'"', 0xff, '"'})} {
		t.Run(name, func(t *testing.T) {
			if ValidateStrictJSON([]byte(data), 1024) == nil {
				t.Fatal("无界/歧义JSON接受")
			}
		})
	}
	if ValidateStrictJSON([]byte(`{}`), 1) == nil {
		t.Fatal("byte limit ignored")
	}
}
func TestIssuerOriginRequiresExactGenesisAnchor(t *testing.T) {
	v := makeOriginFixture(t)
	pin := originPin(v)
	if _, e := VerifyIssuerEvidenceV2(pin, v.Approval.IssuerProof); e == nil {
		t.Fatal("无独立initial锚接受")
	}
	initial := proofGenesisV2(v.Approval.IssuerProof)
	if _, e := VerifyIssuerEvidenceV2(pin, v.Approval.IssuerProof, initial...); e != nil {
		t.Fatal(e)
	}
	initial[0].Grant.EnvironmentID = "fresh-server-Y"
	if _, e := VerifyIssuerEvidenceV2(pin, v.Approval.IssuerProof, initial...); e == nil {
		t.Fatal("替换精确genesis接受")
	}
}
