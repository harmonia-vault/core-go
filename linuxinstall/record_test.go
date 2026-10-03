package linuxinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func syntheticReceipt(t *testing.T) Receipt {
	p := syntheticPlan(t)
	u, _ := p.Unit()
	s := sha256.Sum256([]byte(u.Content))
	return Receipt{Schema: ReceiptSchema, InstallationID: strings.Repeat("1", 32), Plan: p, UnitSHA256: hex.EncodeToString(s[:]), Phase: "installed-disabled"}
}
func syntheticJournal(t *testing.T, phase string) Journal {
	r := syntheticReceipt(t)
	j := Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: r.Plan, Phase: phase, Revision: 1, Deletions: []Deletion{}}
	if journalPhases[phase] >= 3 {
		j.Deletions = []Deletion{
			{Object: Identity{Area: "state-directory", Name: "10001", Kind: "directory", Device: 1, Inode: 1, Mode: 0700, Links: 2}},
			{Object: Identity{Area: "program-directory", Name: "10001", Kind: "directory", Device: 1, Inode: 2, Mode: 0755, Links: 2}},
			{Object: Identity{Area: "program", Name: "harmonia", Kind: "file", Device: 1, Inode: 3, Mode: 0755, Links: 1}},
			{Object: Identity{Area: "unit", Name: r.Plan.UnitName, Kind: "file", Device: 1, Inode: 4, Mode: 0644, Links: 1}},
		}
	}
	return j
}
func cloneJournal(j Journal) Journal { j.Deletions = append([]Deletion(nil), j.Deletions...); return j }
func TestRecordsStrictSchemaAndGeneratedUnitBinding(t *testing.T) {
	r := syntheticReceipt(t)
	b, _ := json.Marshal(r)
	if _, err := DecodeReceipt(b); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, value string }{{"unknown", strings.TrimSuffix(string(b), "}") + `,"arbitraryDelete":"/home/lab"}`}, {"duplicate", strings.TrimSuffix(string(b), "}") + `,"phase":"enabled"}`}, {"trailer", string(b) + " {}"}, {"oversize", strings.Repeat(" ", MaxRecordBytes+1) + string(b)}} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := DecodeReceipt([]byte(c.value)); err != ErrState {
				t.Fatal("malformed root record accepted")
			}
		})
	}
	r.UnitSHA256 = strings.Repeat("f", 64)
	if r.Validate() != ErrState {
		t.Fatal("receipt authenticated arbitrary unit instead of fixed plan")
	}
	j := syntheticJournal(t, "cleanup-authorized")
	b, _ = json.Marshal(j)
	if _, err := DecodeJournal(b); err != nil {
		t.Fatal(err)
	}
}
func TestAccountSlotsAndArbitraryFilesNeverEnterCleanupPlan(t *testing.T) {
	base := syntheticJournal(t, "cleanup-authorized")
	for _, name := range []string{"device.v1.enc", "session.v1.enc", "trust.v1.enc", "writes.v1.enc", "recovery.dag.v1.enc", "windows-originals.v1.enc", "../other", ".localkeys-0123456789abcdef0123456789abcdef"} {
		t.Run(name, func(t *testing.T) {
			j := cloneJournal(base)
			j.Deletions = append(j.Deletions, Deletion{Object: Identity{Area: "state", Name: name, Kind: "file", Device: 1, Inode: 22, UID: 10001, GID: 10001, Mode: 0600, Links: 1}})
			if j.Validate() != ErrState {
				t.Fatal("new identity or unknown file admitted to cleanup")
			}
		})
	}
	j := cloneJournal(base)
	j.Deletions[2].Object.Links = 2
	if j.Validate() != ErrState {
		t.Fatal("hardlink accepted")
	}
	j = cloneJournal(base)
	j.Deletions = j.Deletions[1:]
	if j.Validate() != ErrState {
		t.Fatal("plan omitting UID root accepted")
	}
	j = cloneJournal(base)
	j.Deletions = append(j.Deletions, j.Deletions[0])
	if j.Validate() != ErrState {
		t.Fatal("duplicate deletion accepted")
	}
	for _, target := range []string{base.Plan.UnitPath, "../" + base.Plan.UnitName} {
		i := Identity{Area: "enable-link", Name: base.Plan.UnitName, Kind: "symlink", Device: 1, Inode: 33, Mode: 0777, Links: 1, LinkTarget: target}
		if i.validate(base.Plan) != nil {
			t.Fatal("fixed systemctl enable target rejected")
		}
		i.LinkTarget = "../../alien.service"
		if i.validate(base.Plan) != ErrState {
			t.Fatal("foreign enable target accepted")
		}
	}
}
func TestPersistentIntentBeforeRemovalAndImmutableRetry(t *testing.T) {
	a := syntheticJournal(t, "cleanup-authorized")
	b := cloneJournal(a)
	b.Revision++
	b.Deletions[0].Intent = true
	if ValidateSuccessor(a, b) != nil || MissingObjectAllowed(a, 0) || !MissingObjectAllowed(b, 0) {
		t.Fatal("delete intent ordering failed")
	}
	c := cloneJournal(b)
	c.Revision++
	c.Deletions[0].Removed = true
	if ValidateSuccessor(b, c) != nil {
		t.Fatal("authorized removal rejected")
	}
	for _, v := range []struct {
		name   string
		mutate func(*Journal)
	}{
		{"advanceWithoutPriorIntent", func(j *Journal) { j.Deletions[1].Intent = true; j.Deletions[1].Removed = true }},
		{"inodeSwap", func(j *Journal) { j.Deletions[0].Object.Inode++ }},
		{"rollback", func(j *Journal) { j.Deletions[0].Intent = false }},
		{"differentInstall", func(j *Journal) { j.InstallationID = strings.Repeat("2", 32) }},
		{"differentPlan", func(j *Journal) { j.Plan.Input.UID = "10002" }},
		{"skippedRevision", func(j *Journal) { j.Revision++ }},
		{"skipPhase", func(j *Journal) { j.Phase = "completed" }},
	} {
		t.Run(v.name, func(t *testing.T) {
			next := cloneJournal(c)
			next.Revision++
			v.mutate(&next)
			if ValidateSuccessor(c, next) == nil {
				t.Fatal("unsafe retry accepted")
			}
		})
	}
	if MissingObjectAllowed(c, -1) || MissingObjectAllowed(c, 4) {
		t.Fatal("missing outside plan accepted")
	}
}
func TestNewCleanupAuthorizationIsNotAnEmptyOrPreRemovedPlan(t *testing.T) {
	a := syntheticJournal(t, "offline-closed")
	b := syntheticJournal(t, "cleanup-authorized")
	b.Revision = a.Revision + 1
	if ValidateSuccessor(a, b) != nil {
		t.Fatal("fixed untouched cleanup plan rejected")
	}
	b.Deletions[0].Intent = true
	if ValidateSuccessor(a, b) != ErrState {
		t.Fatal("initial plan already assumed deletion")
	}
	b = cloneJournal(a)
	b.Phase = "cleanup-authorized"
	b.Revision++
	if b.Validate() != ErrState {
		t.Fatal("empty cleanup plan claimed success")
	}
}
