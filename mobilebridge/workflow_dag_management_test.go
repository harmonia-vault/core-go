package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/mobileworkflow"
)

func TestDAGManagementExactIndependentCommandAndMetadata(t *testing.T) {
	valid := `{"version":1,"endpoint":"https://synthetic.example","operation":"prepareDAGDeviceGrant","requestId":"synthetic-grant","environmentId":"synthetic-env","subjectDeviceId":"synthetic-device","role":"none","expiresAt":"0"}`
	if e := ValidateDAGManagementCommand(valid); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{strings.Replace(valid, `"expiresAt":"0"`, `"expiresAt":"1"`, 1), strings.Replace(valid, `"role":"none"`, `"role":"Admin"`, 1), strings.Replace(valid, `"expiresAt":"0"`, `"expiresAt":"00"`, 1), strings.Replace(valid, `"requestId":"synthetic-grant"`, `"requestId":"`+strings.Repeat("a", 65)+`"`, 1), strings.Replace(valid, `"version":1`, `"version":1,"token":"synthetic"`, 1), strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(valid, `"operation":"prepareDAGDeviceGrant"`, `"operation":"prepareOtherDeviceRevocation"`, 1)} {
		if e := ValidateDAGManagementCommand(raw); e == nil {
			t.Fatal("unsafe or unknown management command accepted")
		}
	}
	if _, e := parseWorkflowCommand(valid); e == nil {
		t.Fatal("ordinary entry accepts DAG management")
	}
	raw, e := DAGManagementProfile()
	if e != nil {
		t.Fatal(e)
	}
	var profile map[string]any
	if json.Unmarshal([]byte(raw), &profile) != nil || len(profile["operations"].([]any)) != 5 {
		t.Fatal("separate profile")
	}
	x := mobileworkflow.DAGManagementInfo{State: "pending", RequestID: "synthetic-id", EnvironmentID: "synthetic-env", SubjectDeviceID: "synthetic-device", Role: "rw", Attempted: true}
	row, e := nativeDAGManagementInfo(x)
	if e != nil || row["sequence"] != "0" || row["applied"] != false {
		t.Fatal("unknown metadata", e)
	}
	x.State = "accepted-not-applied"
	x.Sequence = 9
	row, e = nativeDAGManagementInfo(x)
	if e != nil || row["sequence"] != "9" || row["applied"] != false {
		t.Fatal("accepted metadata", e)
	}
	x.Applied = true
	if _, e = nativeDAGManagementInfo(x); e == nil {
		t.Fatal("metadata promoted without final state")
	}
	if _, e = nativeDAGManagementInfo(mobileworkflow.DAGManagementInfo{State: "none", RequestID: "synthetic-id"}); e == nil {
		t.Fatal("none retained original metadata")
	}
	if _, e = nativeDAGManagementDevices([]mobileworkflow.ManagementDevice{{DeviceID: "synthetic-device", Role: "ungranted", GrantGeneration: "1"}}); e == nil {
		t.Fatal("ungranted fabricated highest generation")
	}
}
