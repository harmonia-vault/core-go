package linuxinstall

import "encoding/json"

// Creation 在首次创建前保存 intent，之后只保存公开 inode 身份，不记录材料。
type Creation struct {
	Area     string    `json:"area"`
	Name     string    `json:"name"`
	Intent   bool      `json:"intent"`
	Observed *Identity `json:"observed,omitempty"`
}

func creationPlan(p Plan) []Creation {
	r := []Creation{{Area: "program-directory", Name: p.Input.UID}, {Area: "program", Name: "harmonia"}}
	if p.CAPath != "" {
		r = append(r, Creation{Area: "program", Name: "ca.pem"})
	}
	return append(r, Creation{Area: "unit", Name: p.UnitName}, Creation{Area: "state-directory", Name: p.Input.UID})
}
func validateCreationRecord(r Receipt) error {
	if r.Revision == 0 {
		if len(r.Creations) != 0 || r.HandoffIntent || r.EnableIntent || r.EnableIdentity != nil {
			return ErrState
		}
		return nil
	}
	want := creationPlan(r.Plan)
	if len(r.Creations) != len(want) {
		return ErrState
	}
	all := true
	for n, c := range r.Creations {
		if c.Area != want[n].Area || c.Name != want[n].Name || c.Observed != nil && !c.Intent {
			return ErrState
		}
		if c.Observed == nil {
			all = false
			continue
		}
		i := *c.Observed
		if i.Area != c.Area || i.Name != c.Name || i.UID != 0 || i.GID != 0 || i.Inode == 0 || i.Links == 0 {
			return ErrState
		}
		if c.Area == "state-directory" || c.Area == "program-directory" {
			if i.Kind != "directory" || i.Mode != 0700 {
				return ErrState
			}
		} else if i.validate(r.Plan) != nil {
			return ErrState
		}
	}
	if r.HandoffIntent && !all {
		return ErrState
	}
	if r.Phase != "install-planned" && (!all || !r.HandoffIntent) {
		return ErrState
	}
	if r.EnableIntent && r.Phase == "install-planned" {
		return ErrState
	}
	if r.EnableIdentity != nil && (!r.EnableIntent || r.EnableIdentity.validate(r.Plan) != nil || r.EnableIdentity.Area != "enable-link") {
		return ErrState
	}
	if r.Phase == "enabled" && r.EnableIdentity == nil {
		return ErrState
	}
	return nil
}
func ValidateReceiptSuccessor(a, b Receipt) error {
	if a.Validate() != nil || b.Validate() != nil || a.Revision == 0 || a.Revision == ^uint64(0) || b.Revision != a.Revision+1 || a.Plan != b.Plan || a.InstallationID != b.InstallationID || a.UnitSHA256 != b.UnitSHA256 || len(a.Creations) != len(b.Creations) || a.HandoffIntent && !b.HandoffIntent || a.EnableIntent && !b.EnableIntent {
		return ErrState
	}
	stages := map[string]int{"install-planned": 0, "installed-disabled": 1, "enabled": 2}
	if stages[b.Phase] < stages[a.Phase] || stages[b.Phase] > stages[a.Phase]+1 {
		return ErrState
	}
	for n, old := range a.Creations {
		c := b.Creations[n]
		if old.Area != c.Area || old.Name != c.Name || old.Intent && !c.Intent {
			return ErrState
		}
		if old.Observed != nil {
			x, _ := json.Marshal(old.Observed)
			y, _ := json.Marshal(c.Observed)
			if string(x) != string(y) {
				return ErrState
			}
		}
	}
	if a.EnableIdentity != nil {
		x, _ := json.Marshal(a.EnableIdentity)
		y, _ := json.Marshal(b.EnableIdentity)
		if string(x) != string(y) {
			return ErrState
		}
	}
	return nil
}

func creationTemporaryName(r Receipt, c Creation) string {
	return ".harmonia-install-" + r.InstallationID + "-" + c.Name
}
func copyReceipt(r Receipt) Receipt {
	b, _ := json.Marshal(r)
	var out Receipt
	_ = json.Unmarshal(b, &out)
	return out
}
func copyJournalRecord(j Journal) Journal {
	b, _ := json.Marshal(j)
	var out Journal
	_ = json.Unmarshal(b, &out)
	return out
}
