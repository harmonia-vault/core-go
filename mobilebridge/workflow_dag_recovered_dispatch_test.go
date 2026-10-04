package mobilebridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"github.com/harmonia-vault/core-go/syncclient"
)

func recoveredNativeCommand(op string, fields map[string]string) string {
	out := map[string]any{"version": 1, "endpoint": "https://synthetic.example.invalid", "operation": op}
	for k, v := range fields {
		out[k] = v
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}
func validRecoveredFields() map[string]string {
	return map[string]string{"expectedSequence": "2", "recoveryHeadHash": strings.Repeat("a", 64), "selections": `[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"0"}]`}
}
func TestNativeDAGRecoveredStrictExplicitSelections(t *testing.T) {
	fields := validRecoveredFields()
	if ValidateDAGRecoveryCommand(recoveredNativeCommand("sealDAGRecoveredDevice", fields), 0) != nil {
		t.Fatal("valid explicit intent")
	}
	for _, selected := range []string{
		`[]`, `null`, `{}`, `[{"environmentId":"env","role":"ro","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"0","seed":"synthetic"}]`,
		`[{"environmentId":"env","EnvironmentId":"env","role":"ro","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","role":"rw","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":null}]`,
		`[{"environmentId":"env","keyVersion":"01","role":"ro","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"Admin","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"-1"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"9223372036854775808"}]`,
		`[{"environmentId":"../env","keyVersion":"1","role":"ro","expiresAt":"0"}]`,
		`[{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"0"},{"environmentId":"env","keyVersion":"1","role":"rw","expiresAt":"0"}]`,
	} {
		fields["selections"] = selected
		if ValidateDAGRecoveryCommand(recoveredNativeCommand("sealDAGRecoveredDevice", fields), 0) == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	for k, v := range map[string]string{"expectedSequence": "02", "recoveryHeadHash": strings.Repeat("A", 64)} {
		f := validRecoveredFields()
		f[k] = v
		if ValidateDAGRecoveryCommand(recoveredNativeCommand("sealDAGRecoveredDevice", f), 0) == nil {
			t.Fatal("noncanonical bound accepted")
		}
	}
	f := validRecoveredFields()
	row := `{"environmentId":"env","keyVersion":"1","role":"ro","expiresAt":"0"}`
	f["selections"] = "[" + strings.Repeat(row+",", 16) + row + "]"
	if ValidateDAGRecoveryCommand(recoveredNativeCommand("sealDAGRecoveredDevice", f), 0) == nil {
		t.Fatal("selection quota accepted")
	}
	for _, operation := range []string{"resolveDAGRecoveryOriginal", "closeDAGRecoveryOriginal"} {
		if ValidateDAGRecoveryCommand(dagCommand(operation), 0) == nil {
			t.Fatal("future business surface accepted")
		}
	}
}
func TestNativeDAGRecoveredMetadataRemainsUntrusted(t *testing.T) {
	choices := mobileworkflow.DAGRecoveredChoices{Version: 1, Profile: cryptox.RecoveryDAGCapability, Sequence: math.MaxUint64, RecoveryHeadHash: strings.Repeat("a", 64), Environments: []cryptox.RecoveryEnvironmentVersion{{EnvironmentID: "env", KeyVersion: "1"}}}
	p, e := nativeDAGRecoveredChoices(choices)
	if e != nil || p["sequence"] != "18446744073709551615" || p["trustedDevice"] != false {
		t.Fatal("precision/trust changed")
	}
	info := mobileworkflow.DAGRecoveredInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, State: "accepted-not-device-applied", OperationID: "original", Acceptance: "accepted", AcceptedSequence: math.MaxUint64, OriginalConfirmed: true}
	pending := mobileworkflow.RecoveryDAGPendingInfo{Version: 1, Profile: cryptox.RecoveryDAGCapability, Kind: "recovered-v2", OperationID: "original", ContentHash: strings.Repeat("b", 64), AcceptedSequence: math.MaxUint64, OriginalApplied: true}
	p, e = nativeDAGRecoveredInfo(info, pending)
	if e != nil || p["acceptedSequence"] != "18446744073709551615" || p["contentHash"] != pending.ContentHash || p["trustedDevice"] != false {
		t.Fatal("sealed binding changed")
	}
	b, _ := json.Marshal(p)
	for _, k := range []string{"privateKey", "sessionToken", "ciphertext", "recoveryCode", "envelope", "selectedRights"} {
		if bytes.Contains(b, []byte(k)) {
			t.Fatal("secret/wire in projection")
		}
	}
	pending.OperationID = "different"
	if _, e = nativeDAGRecoveredInfo(info, pending); e == nil {
		t.Fatal("metadata mixed original IDs")
	}
	choices.TrustedDevice = true
	if _, e = nativeDAGRecoveredChoices(choices); e == nil {
		t.Fatal("trusted projection accepted")
	}
}
func TestNativeDAGRecoveredRetryCannotSelectNewOriginal(t *testing.T) {
	d, e := NewDevice()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	r, _ := NewNativeDAGRegistry("synthetic.native", "slot", 41)
	defer r.Close()
	v, e := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic.native\x00harmonia/workflow-state/v1\x00slot", nil, nil, &typedAtomicNativeFixture{})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	if e = v.AttachDAGRegistry(r); e != nil {
		t.Fatal(e)
	}
	raw := recoveredNativeCommand("retryDAGRecoveredDevice", map[string]string{"operationId": "unaccepted-id", "contentHash": strings.Repeat("a", 64)})
	if _, e = v.ExecuteDAGRecovery(raw, nil); !errors.Is(e, errInput) || !r.dead.Load() {
		t.Fatal("no original retry accepted")
	}
}
func TestNativeDAGRecoveredSoftNeverSwallowsHardFault(t *testing.T) {
	for _, hard := range []error{mobileworkflow.ErrDAGPersistence, mobileworkflow.ErrDAGOwnerBinding, cryptox.ErrInvalidWire, syncclient.ErrTrustInvalidated, &syncclient.RequestError{Status: 401}, &syncclient.RequestError{Status: 403}} {
		if nativeDAGSoftCandidate("sealDAGRecoveredDevice", errors.Join(syncclient.ErrDAGPreparationPending, hard)) || nativeDAGSoftCandidate("retryDAGRecoveredDevice", errors.Join(syncclient.ErrEnrollmentPending, hard)) {
			t.Fatal("hard fault became retryable")
		}
	}
	if !nativeDAGSoftCandidate("sealDAGRecoveredDevice", syncclient.ErrDAGPreparationPending) || !nativeDAGSoftCandidate("retryDAGRecoveredDevice", errors.Join(syncclient.ErrEnrollmentPending, &syncclient.RequestError{Status: 504})) {
		t.Fatal("original soft boundary lost")
	}
	if nativeDAGSoftCandidate("dagRecoveredEnrollmentChoices", syncclient.ErrEnrollmentPending) {
		t.Fatal("choices generalized")
	}
}
