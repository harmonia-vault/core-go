package linuxinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Captured from the unmodified public e354 generator before this fix. These
// independent historical bytes prevent compatibility from drifting with a helper.
func oldUnitGolden(t *testing.T, ca bool) (Plan, []byte) {
	t.Helper()
	plan := syntheticPlan(t)
	name := "simple-v1.service"
	if ca {
		in := plan.Input
		in.CASource = "/opt/harmonia-test/ca.pem"
		in.CASHA256 = strings.Repeat("b", 64)
		var err error
		plan, err = NewPlan(in)
		if err != nil {
			t.Fatal(err)
		}
		name = "simple-v1-ca.service"
	}
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return plan, data
}

func oldReceipt(t *testing.T, ca bool, phase string) (Receipt, []byte) {
	t.Helper()
	plan, body := oldUnitGolden(t, ca)
	r := currentReceipt(t)
	r.Plan = plan
	r.Creations = creationPlan(plan)
	r.UnitSHA256 = unitDigest(body)
	if phase != "install-planned" {
		r = observeAll(t, r)
		r.HandoffIntent = true
	}
	r.Phase = phase
	if phase == "enabled" {
		r.EnableIntent = true
		r.EnableIdentity = &Identity{Area: "enable-link", Name: plan.UnitName, Kind: "symlink", Device: 1, Inode: 999, Mode: 0777, Links: 1, LinkTarget: plan.UnitPath}
	}
	return r, body
}

func TestHistoricalSimpleReceiptsAndUninstallJournalKeepExactUnit(t *testing.T) {
	for _, ca := range []bool{false, true} {
		for _, phase := range []string{"install-planned", "installed-disabled", "enabled"} {
			name := phase
			if ca {
				name += "-ca"
			}
			t.Run(name, func(t *testing.T) {
				r, body := oldReceipt(t, ca, phase)
				encoded, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				restored, err := DecodeReceipt(encoded)
				if err != nil || restored.UnitSHA256 != unitDigest(body) {
					t.Fatal("historical receipt rejected or changed", err)
				}
				template, err := restored.unitTemplate()
				if err != nil || !bytes.Equal(template.Content, body) {
					t.Fatal("historical unit silently migrated", err)
				}
				next := copyReceipt(restored)
				next.Revision++
				if ValidateReceiptSuccessor(restored, next) != nil {
					t.Fatal("historical immutable receipt retry rejected")
				}
				j := Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: r.Plan, Phase: "uninstall-requested", Revision: 1, Receipt: &restored}
				encoded, err = json.Marshal(j)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = DecodeJournal(encoded); err != nil {
					t.Fatal("historical receipt blocked uninstall journal", err)
				}
				// No CAS may change the full template contract to the newly generated exec hash.
				current, err := r.Plan.Unit()
				if err != nil {
					t.Fatal(err)
				}
				next.UnitSHA256 = unitDigest(current.Content)
				if ValidateReceiptSuccessor(restored, next) != ErrState {
					t.Fatal("old receipt digest silently upgraded")
				}
			})
		}
	}
}

func TestNewPlansUseExecAndRejectUnknownHistoricalBodies(t *testing.T) {
	plan, old := oldUnitGolden(t, false)
	current, err := plan.Unit()
	if err != nil || bytes.Count(current.Content, []byte("\nType=exec\n")) != 1 || bytes.Contains(current.Content, []byte("\nType=simple\n")) {
		t.Fatal("new plan lacks exec readiness boundary", err)
	}
	r := currentReceipt(t)
	if r.UnitSHA256 != unitDigest(current.Content) {
		t.Fatal("fresh receipt did not commit exec unit")
	}
	for _, body := range [][]byte{
		append(append([]byte(nil), old...), []byte("ExecStart=/bin/sh\n")...),
		bytes.Replace(old, []byte("NoNewPrivileges=true"), []byte("NoNewPrivileges=false"), 1),
		bytes.Replace(old, []byte("User=harmonia_lab"), []byte("User=root"), 1),
		bytes.Replace(old, []byte("Type=simple"), []byte("Type=notify"), 1),
	} {
		forged := copyReceipt(r)
		forged.UnitSHA256 = unitDigest(body)
		if forged.Validate() != ErrState {
			t.Fatal("arbitrary historical template hash accepted")
		}
	}
	bad := copyReceipt(r)
	bad.UnitSHA256 = strings.Repeat("f", 64)
	if _, err := bad.unitTemplate(); err != ErrState {
		t.Fatal("unknown hash accepted", err)
	}
}

func TestStoppedHistoricalPendingEnableReceiptAndJournalRemainUsable(t *testing.T) {
	r, body := oldReceipt(t, true, "installed-disabled")
	r.Revision = 15
	r.EnableIntent = true
	r.EnableIdentity = &Identity{Area: "enable-link", Name: r.Plan.UnitName, Kind: "symlink", Device: 1, Inode: 999, Mode: 0777, Links: 1, LinkTarget: r.Plan.UnitPath}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeReceipt(encoded)
	if err != nil || restored.Phase != "installed-disabled" || restored.Revision != 15 || restored.UnitSHA256 != unitDigest(body) {
		t.Fatal("pending enabled-but-stopped historical receipt rejected", err)
	}
	j := Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: r.Plan, Phase: "uninstall-requested", Revision: 1, Receipt: &restored}
	encoded, err = json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	old, err := DecodeJournal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	next := copyJournalRecord(old)
	next.Revision++
	next.Phase = "service-drained"
	if ValidateSuccessor(old, next) != nil {
		t.Fatal("normal stop journal advancement rejected")
	}
	forged := copyJournalRecord(next)
	current, _ := r.Plan.Unit()
	forged.Receipt.UnitSHA256 = unitDigest(current.Content)
	if ValidateSuccessor(old, forged) != ErrState {
		t.Fatal("legacy journal replaced frozen template")
	}
}

func TestEffectiveUnitTypeCannotSilentlyFallBack(t *testing.T) {
	if decodeUnitTypeResponse([]byte("Type=exec\n"), []byte("warning\n"), "exec") != ErrState || decodeUnitTypeResponse([]byte("Type=exec\n"), nil, "exec") != nil {
		t.Fatal("effective type query accepted stderr or rejected exact response")
	}
	if decodeUnitType([]byte("Type=exec\n"), "exec") != nil || decodeUnitType([]byte("Type=simple\n"), "simple") != nil {
		t.Fatal("exact effective type rejected")
	}
	if decodeUnitType([]byte("Type=simple\n"), "exec") != ErrUnsupported || decodeUnitType([]byte("Type=exec\n"), "simple") != ErrUnsupported {
		t.Fatal("mismatched readiness contract accepted")
	}
	for _, value := range []string{"", "Type=notify\n", "Type=exec\nType=simple\n", "Type=exec\nInjected=true\n", "exec\n", "Type=exec"} {
		if decodeUnitType([]byte(value), "exec") != ErrState {
			t.Fatal("unknown or malformed type admitted")
		}
	}
}
