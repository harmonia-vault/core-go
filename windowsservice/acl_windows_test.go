//go:build windows

package windowsservice

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestNativeACLReplacementBoundary(t *testing.T) {
	cases := []struct {
		label, sddl string
		check       func(*windows.SECURITY_DESCRIPTOR) error
		accept      bool
	}{
		{"protected leaf", `O:SYG:SYD:P(A;;FA;;;SY)(A;;GRGX;;;BU)`, func(s *windows.SECURITY_DESCRIPTOR) error { return immutableACL(s, nil) }, true},
		{"mutable leaf", `O:SYG:SYD:P(A;;FA;;;SY)(A;;FW;;;BU)`, func(s *windows.SECURITY_DESCRIPTOR) error { return immutableACL(s, nil) }, false},
		{"root create subdir", `O:SYG:SYD:(A;;FA;;;SY)(A;;0x4;;;AU)`, ancestorACL, true},
		{"inherit-only full", `O:SYG:SYD:(A;;FA;;;SY)(A;OICIIO;FA;;;CO)(A;;GRGX;;;BU)`, ancestorACL, true},
		{"ancestor delete child", `O:SYG:SYD:(A;;FA;;;SY)(A;;0x40;;;BU)`, ancestorACL, false},
		{"ancestor write attrs", `O:SYG:SYD:(A;;FA;;;SY)(A;;0x100;;;BU)`, ancestorACL, false},
		{"scheduler other creates", `O:BAG:SYD:(A;;FA;;;SY)(A;;0x6;;;AU)`, schedulerTopACL, true},
		{"scheduler standard create rights", `O:BAG:SYD:(A;;FA;;;SY)(A;;0x120116;;;AU)`, schedulerTopACL, true},
		{"scheduler delete child", `O:BAG:SYD:(A;;FA;;;SY)(A;;0x40;;;AU)`, schedulerTopACL, false},
		{"scheduler generic write", `O:BAG:SYD:(A;;FA;;;SY)(A;;GW;;;AU)`, schedulerTopACL, false},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if (c.check(sd) == nil) != c.accept {
				t.Fatalf("unexpected ACL policy for %s", c.label)
			}
		})
	}
}
