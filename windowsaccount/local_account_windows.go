//go:build windows

package windowsaccount

import "golang.org/x/sys/windows"

type nativeSAMLookup struct{}

func (nativeSAMLookup) ComputerName() (string, error) { return windows.ComputerName() }
func (nativeSAMLookup) NameToSID(name string) (samIdentity, error) {
	sid, domain, kind, err := windows.LookupSID("", name)
	if err != nil || sid == nil {
		return samIdentity{}, ErrIdentity
	}
	return samIdentity{SID: sid.String(), Domain: domain, Kind: kind}, nil
}
func (nativeSAMLookup) SIDToName(value string) (samIdentity, error) {
	sid, err := windows.StringToSid(value)
	if err != nil {
		return samIdentity{}, ErrIdentity
	}
	name, domain, kind, err := sid.LookupAccount("")
	if err != nil {
		return samIdentity{}, ErrIdentity
	}
	return samIdentity{SID: sid.String(), Name: name, Domain: domain, Kind: kind}, nil
}
func verifyLocalPlanAccount(p Plan) error { return checkPlanLocalAccount(p, nativeSAMLookup{}) }
func verifyConfiguredLocalPlanAccount(p Plan, name string) error {
	return checkConfiguredLocalAccount(p, name, nativeSAMLookup{})
}
