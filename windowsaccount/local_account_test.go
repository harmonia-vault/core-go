package windowsaccount

import (
	"errors"
	"strings"
	"testing"
)

type fakeSAMLookup struct {
	computer                            string
	forward, reverse                    samIdentity
	computerErr, forwardErr, reverseErr error
	names, sids                         []string
}

func (f *fakeSAMLookup) ComputerName() (string, error) { return f.computer, f.computerErr }
func (f *fakeSAMLookup) NameToSID(name string) (samIdentity, error) {
	f.names = append(f.names, name)
	return f.forward, f.forwardErr
}
func (f *fakeSAMLookup) SIDToName(sid string) (samIdentity, error) {
	f.sids = append(f.sids, sid)
	return f.reverse, f.reverseErr
}
func goodSAM() *fakeSAMLookup {
	p := testPlan()
	return &fakeSAMLookup{computer: "SYNTHETIC-HOST", forward: samIdentity{SID: p.TargetSID, Domain: "SYNTHETIC-HOST", Kind: 1}, reverse: samIdentity{SID: p.TargetSID, Name: p.LocalUser, Domain: "SYNTHETIC-HOST", Kind: 1}}
}
func TestLocalSAMBindingRequiresQualifiedBidirectionalIdentity(t *testing.T) {
	p := testPlan()
	t.Run("qualified-query-and-reverse-same-SID", func(t *testing.T) {
		f := goodSAM()
		if checkPlanLocalAccount(p, f) != nil || len(f.names) != 1 || f.names[0] != "SYNTHETIC-HOST\\"+p.LocalUser || len(f.sids) != 1 || f.sids[0] != p.TargetSID {
			t.Fatal("did not bind exact local qualified name and reverse SID")
		}
	})
	t.Run("Windows-case-insensitive-config-and-identity", func(t *testing.T) {
		f := goodSAM()
		f.forward.Domain = strings.ToLower(f.forward.Domain)
		f.reverse.Domain = strings.ToLower(f.reverse.Domain)
		f.reverse.Name = strings.ToUpper(f.reverse.Name)
		if checkConfiguredLocalAccount(p, ".\\HARMONIA-TEST", f) != nil {
			t.Fatal("valid Windows case variation rejected")
		}
	})
	t.Run("real-local-qualified-SCM-name", func(t *testing.T) {
		if checkConfiguredLocalAccount(p, "synthetic-host\\"+p.LocalUser, goodSAM()) != nil {
			t.Fatal("qualified local SCM identity rejected")
		}
	})
	failure := errors.New("synthetic lookup failure")
	faults := map[string]func(*fakeSAMLookup){
		"computer-read":                    func(f *fakeSAMLookup) { f.computerErr = failure },
		"computer-extra-domain":            func(f *fakeSAMLookup) { f.computer = "OTHER\\HOST" },
		"name-query":                       func(f *fakeSAMLookup) { f.forwardErr = failure },
		"forward-foreign-domain-same-name": func(f *fakeSAMLookup) { f.forward.Domain = "FOREIGN" },
		"forward-wrong-SID":                func(f *fakeSAMLookup) { f.forward.SID = "S-1-5-21-111-222-333-1002" },
		"forward-not-user":                 func(f *fakeSAMLookup) { f.forward.Kind = 4 },
		"SID-query":                        func(f *fakeSAMLookup) { f.reverseErr = failure },
		"reverse-wrong-SID":                func(f *fakeSAMLookup) { f.reverse.SID = "S-1-5-21-111-222-333-1002" },
		"reverse-wrong-name":               func(f *fakeSAMLookup) { f.reverse.Name = "another-user" },
		"reverse-extra-domain-in-name":     func(f *fakeSAMLookup) { f.reverse.Name = "OTHER\\" + p.LocalUser },
		"reverse-foreign-domain":           func(f *fakeSAMLookup) { f.reverse.Domain = "FOREIGN" },
		"reverse-not-user":                 func(f *fakeSAMLookup) { f.reverse.Kind = 4 },
	}
	for name, edit := range faults {
		t.Run(name, func(t *testing.T) {
			f := goodSAM()
			edit(f)
			if !errors.Is(checkPlanLocalAccount(p, f), ErrIdentity) {
				t.Fatal("identity fault did not fail closed")
			}
			for _, name := range f.names {
				if name == p.LocalUser || strings.HasPrefix(name, ".\\") {
					t.Fatal("SCM shorthand or bare name leaked into SID query")
				}
			}
		})
	}
	for name, stored := range map[string]string{"stored-bare": p.LocalUser, "stored-foreign": "FOREIGN\\" + p.LocalUser, "stored-extra-separator": ".\\OTHER\\" + p.LocalUser, "stored-other-local": "SYNTHETIC-HOST\\other-user"} {
		t.Run(name, func(t *testing.T) {
			f := goodSAM()
			if !errors.Is(checkConfiguredLocalAccount(p, stored, f), ErrIdentity) || len(f.names) != 0 {
				t.Fatal("invalid stored SCM identity reached permissive lookup")
			}
		})
	}
	t.Run("inventory-local-shorthand", func(t *testing.T) {
		f := goodSAM()
		sid, err := resolveLocalShorthand(".\\"+p.LocalUser, f)
		if err != nil || sid != p.TargetSID || len(f.names) != 1 || f.names[0] != "SYNTHETIC-HOST\\"+p.LocalUser {
			t.Fatal("inventory shorthand not bound to actual local SAM")
		}
	})
	t.Run("inventory-extra-domain-stays-unresolved", func(t *testing.T) {
		f := goodSAM()
		if _, err := resolveLocalShorthand(".\\FOREIGN\\"+p.LocalUser, f); !errors.Is(err, ErrIdentity) || len(f.names) != 0 {
			t.Fatal("inventory alias accepted an extra domain")
		}
	})
}
