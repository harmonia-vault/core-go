package windowsaccount

import (
	"github.com/harmonia-vault/core-go/platform"
	"strings"
)

const localUserSIDKind uint32 = 1 // Windows SID_NAME_USE: SidTypeUser.

type samIdentity struct {
	SID    string
	Name   string
	Domain string
	Kind   uint32
}
type localSAMLookup interface {
	ComputerName() (string, error)
	NameToSID(string) (samIdentity, error)
	SIDToName(string) (samIdentity, error)
}

func samComponent(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value && value != "." && value != ".." && !strings.ContainsAny(value, "\\/\x00\r\n")
}
func lookupComputer(lookup localSAMLookup) (string, error) {
	if lookup == nil {
		return "", ErrIdentity
	}
	computer, err := lookup.ComputerName()
	if err != nil || !samComponent(computer) {
		return "", ErrIdentity
	}
	return computer, nil
}

// resolveSAM never passes SCM's .\ shorthand or a bare name to LookupAccountName.
// Forward and reverse APIs must agree on the same local user, domain, kind and SID.
func resolveSAM(computer, user, targetSID string, lookup localSAMLookup) (string, error) {
	if lookup == nil || !samComponent(computer) || !samComponent(user) || (targetSID != "" && !platform.ValidSID(targetSID)) {
		return "", ErrIdentity
	}
	forward, err := lookup.NameToSID(computer + "\\" + user)
	if err != nil || forward.Kind != localUserSIDKind || !platform.ValidSID(forward.SID) || !strings.EqualFold(forward.Domain, computer) || (targetSID != "" && forward.SID != targetSID) {
		return "", ErrIdentity
	}
	reverse, err := lookup.SIDToName(forward.SID)
	if err != nil || reverse.Kind != localUserSIDKind || reverse.SID != forward.SID || !strings.EqualFold(reverse.Domain, computer) || !strings.EqualFold(reverse.Name, user) || !samComponent(reverse.Name) || !samComponent(reverse.Domain) {
		return "", ErrIdentity
	}
	return forward.SID, nil
}
func checkPlanLocalAccount(p Plan, lookup localSAMLookup) error {
	if p.Validate() != nil {
		return ErrPlan
	}
	computer, err := lookupComputer(lookup)
	if err != nil {
		return err
	}
	_, err = resolveSAM(computer, p.LocalUser, p.TargetSID, lookup)
	return err
}
func checkConfiguredLocalAccount(p Plan, stored string, lookup localSAMLookup) error {
	if p.Validate() != nil {
		return ErrPlan
	}
	computer, err := lookupComputer(lookup)
	if err != nil {
		return err
	}
	// The SCM may retain its documented .\ form or the real local qualified form.
	// Bare names, another domain and extra separators are never accepted.
	if !strings.EqualFold(stored, p.AccountName()) && !strings.EqualFold(stored, computer+"\\"+p.LocalUser) {
		return ErrIdentity
	}
	_, err = resolveSAM(computer, p.LocalUser, p.TargetSID, lookup)
	return err
}
func resolveLocalShorthand(name string, lookup localSAMLookup) (string, error) {
	if !strings.HasPrefix(name, ".\\") {
		return "", ErrIdentity
	}
	computer, err := lookupComputer(lookup)
	if err != nil {
		return "", err
	}
	return resolveSAM(computer, strings.TrimPrefix(name, ".\\"), "", lookup)
}
