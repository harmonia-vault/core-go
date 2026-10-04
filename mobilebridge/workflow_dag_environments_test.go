package mobilebridge

import (
	"bytes"
	"encoding/json"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"strings"
	"testing"
)

func TestDAGEnvironmentExactCommandAndProfile(t *testing.T) {
	raw := `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"createDAGEnvironment","requestId":"synthetic-create","authorityEnvironmentId":"synthetic-authority"}`
	if e := ValidateDAGEnvironmentCommand(raw); e != nil {
		t.Fatal(e)
	}
	for _, x := range []string{
		strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(raw, `"authorityEnvironmentId"`, `"environmentId"`, 1),
		strings.Replace(raw, `"createDAGEnvironment"`, `"createEnvironment"`, 1),
		strings.Replace(raw, `"synthetic-create"`, `"`+strings.Repeat("a", 65)+`"`, 1),
		strings.TrimSuffix(raw, "}") + `,"name":"SYNTHETIC_NAME"}`,
		raw + "{}", raw + strings.Repeat(" ", 4096),
	} {
		if ValidateDAGEnvironmentCommand(x) == nil {
			t.Fatal("nonexact DTO accepted")
		}
	}
	p, e := DAGEnvironmentProfile()
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]any
	if json.Unmarshal([]byte(p), &fields) != nil || len(fields["operations"].([]any)) != 6 {
		t.Fatal("profile")
	}
	ordinary, e := WorkflowProfile()
	if e != nil || strings.Contains(ordinary, "createDAGEnvironment") {
		t.Fatal("ordinary expanded")
	}
	variables, e := DAGBusinessProfile()
	if e != nil || strings.Contains(variables, "createDAGEnvironment") {
		t.Fatal("variables profile expanded")
	}
}
func TestDAGEnvironmentUntrustedConsumesIndependentNames(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-dag-env", nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	for _, input := range []struct {
		op, fields string
		name       []byte
	}{
		{"createDAGEnvironment", `,"requestId":"synthetic-id","authorityEnvironmentId":"synthetic-env"`, []byte("SYNTHETIC_NAME")},
		{"renameDAGEnvironment", `,"requestId":"synthetic-id","environmentId":"synthetic-env"`, []byte(strings.Repeat("界", 121))},
		{"rotateDAGEnvironment", `,"requestId":"synthetic-id","environmentId":"synthetic-env"`, []byte("SYNTHETIC_REJECTED")},
		{"pendingDAGEnvironments", "", nil},
		{"retryDAGEnvironment", `,"requestId":"synthetic-id"`, nil},
	} {
		command := `{"version":1,"endpoint":"https://synthetic.example.invalid","operation":"` + input.op + `"` + input.fields + `}`
		out, e := v.ExecuteDAGEnvironment(command, input.name)
		if e == nil || out != "" || !bytes.Equal(input.name, make([]byte, len(input.name))) {
			t.Fatal("untrusted operation leaked state or buffer", input.op)
		}
	}
}
func TestDAGEnvironmentMetadataExactDecimal(t *testing.T) {
	for _, x := range []mobileworkflow.DAGEnvironmentInfo{
		{RequestID: "synthetic-id", Operation: "create", EnvironmentID: "synthetic-env"},
		{RequestID: "synthetic-id", Operation: "rotate", EnvironmentID: "synthetic-env", Sequence: 9, Applied: true},
	} {
		out, e := nativeDAGEnvironmentInfo(x)
		if e != nil || out["sequence"] != map[bool]string{false: "0", true: "9"}[x.Applied] {
			t.Fatal("metadata converter", e)
		}
	}
	if _, e := nativeDAGEnvironmentInfo(mobileworkflow.DAGEnvironmentInfo{RequestID: "synthetic-id", Operation: "delete", EnvironmentID: "synthetic-env", Applied: true}); e == nil {
		t.Fatal("zero sequence was applied")
	}
}
