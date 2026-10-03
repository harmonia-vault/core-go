package linuxinstall

import (
	"encoding/json"
	"testing"
)

func currentReceipt(t *testing.T) Receipt {
	r := syntheticReceipt(t)
	r.Phase = "install-planned"
	r.Revision = 1
	r.Creations = creationPlan(r.Plan)
	return r
}
func observeAll(t *testing.T, r Receipt) Receipt {
	t.Helper()
	n := copyReceipt(r)
	for k := range n.Creations {
		c := &n.Creations[k]
		c.Intent = true
		i := Identity{Area: c.Area, Name: c.Name, Device: 1, Inode: uint64(k + 1), UID: 0, GID: 0, Kind: "file", Mode: 0644, Links: 1}
		switch c.Area {
		case "program-directory", "state-directory":
			i.Kind = "directory"
			i.Mode = 0700
			i.Links = 2
		case "program":
			if c.Name == "harmonia" {
				i.Mode = 0755
			}
		}
		c.Observed = &i
	}
	if n.Validate() != nil {
		t.Fatal("synthetic current receipt invalid")
	}
	return n
}
func TestCreationJournalNeverPromotesUnknownOrChangesFrozenIdentity(t *testing.T) {
	r := currentReceipt(t)
	n := copyReceipt(r)
	n.Revision++
	n.Creations[0].Intent = true
	if ValidateReceiptSuccessor(r, n) != nil {
		t.Fatal("intent rejected")
	}
	r = n
	n = copyReceipt(r)
	n.Revision++
	n.Creations[0].Observed = &Identity{Area: "program-directory", Name: r.Plan.Input.UID, Kind: "directory", Device: 1, Inode: 2, Mode: 0700, Links: 2}
	if ValidateReceiptSuccessor(r, n) != nil {
		t.Fatal("observed own directory rejected")
	}
	r = n
	for _, test := range []struct {
		name   string
		mutate func(*Receipt)
	}{
		{"clearIntent", func(n *Receipt) { n.Creations[0].Intent = false }},
		{"replaceInode", func(n *Receipt) { n.Creations[0].Observed.Inode++ }},
		{"foreignScope", func(n *Receipt) { n.Creations[0].Name = "10002" }},
		{"handoffBeforeAllObjects", func(n *Receipt) { n.HandoffIntent = true }},
		{"enableBeforeHandoff", func(n *Receipt) { n.EnableIntent = true }},
		{"jumpToEnabled", func(n *Receipt) { n.Phase = "enabled" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			n := copyReceipt(r)
			n.Revision++
			test.mutate(&n)
			if ValidateReceiptSuccessor(r, n) == nil {
				t.Fatal("unsafe receipt progression")
			}
		})
	}
}
func TestPartialInstallationCleanupRequiresOnlyExactObservedSnapshot(t *testing.T) {
	r := currentReceipt(t)
	r.Creations[0].Intent = true
	r.Creations[0].Observed = &Identity{Area: "program-directory", Name: r.Plan.Input.UID, Kind: "directory", Device: 1, Inode: 2, Mode: 0700, Links: 2}
	j := Journal{Schema: JournalSchema, InstallationID: r.InstallationID, Plan: r.Plan, Phase: "cleanup-authorized", Revision: 4, Receipt: &r, Deletions: []Deletion{{Object: *r.Creations[0].Observed}}}
	if j.Validate() != nil {
		t.Fatal("partial installation precise cleanup rejected")
	}
	bad := copyJournalRecord(j)
	bad.Deletions = nil
	if bad.Validate() == nil {
		t.Fatal("created object disappeared from plan")
	}
	old := copyJournalRecord(j)
	old.Phase = "offline-closed"
	old.Revision--
	old.Deletions = nil
	if ValidateSuccessor(old, j) != nil {
		t.Fatal("exact frozen partial plan rejected")
	}
	forged := copyJournalRecord(j)
	forged.Receipt.Creations[0].Observed.Inode++
	if ValidateSuccessor(old, forged) == nil {
		t.Fatal("snapshot changed while authorizing deletion")
	}
	old.Phase = "uninstall-requested"
	old.Receipt.InstallationID = "not-valid"
	if old.Validate() == nil {
		t.Fatal("early phase accepted invalid snapshot")
	}
}
func TestFrozenGenesisReceiptCannotBecomeEnabledWithoutOwnedLink(t *testing.T) {
	r := observeAll(t, currentReceipt(t))
	r.HandoffIntent = true
	r.Phase = "installed-disabled"
	n := copyReceipt(r)
	n.Revision++
	n.EnableIntent = true
	if ValidateReceiptSuccessor(r, n) != nil {
		t.Fatal("explicit enable intent rejected")
	}
	r = n
	n = copyReceipt(r)
	n.Revision++
	n.Phase = "enabled"
	if ValidateReceiptSuccessor(r, n) == nil {
		t.Fatal("enabled without exact symlink")
	}
	i := Identity{Area: "enable-link", Name: r.Plan.UnitName, Kind: "symlink", Device: 1, Inode: 9, Mode: 0777, Links: 1, LinkTarget: r.Plan.UnitPath}
	n.EnableIdentity = &i
	if ValidateReceiptSuccessor(r, n) != nil {
		t.Fatal("valid exact enable link rejected")
	}
	b, e := json.Marshal(n)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeReceipt(b); e != nil {
		t.Fatal(e)
	}
}
func TestEnrollmentCompletionOnlyAcceptsMatureExactContract(t *testing.T) {
	if decodeEnrollmentCompletion([]byte(`{"version":1,"localEnrollmentVerified":true}`)) != nil {
		t.Fatal("mature contract rejected")
	}
	for _, s := range []string{`{"version":1,"localEnrollmentVerified":false}`, `{"version":1,"trusted":true}`, `{"version":1,"localEnrollmentVerified":true,"localEnrollmentVerified":false}`, `{"version":2,"localEnrollmentVerified":true}`, `{"version":1,"localEnrollmentVerified":true} {}`} {
		if decodeEnrollmentCompletion([]byte(s)) == nil {
			t.Fatal("invalid enrollment shortcut")
		}
	}
}
