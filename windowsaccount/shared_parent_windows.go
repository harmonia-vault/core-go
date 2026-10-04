//go:build windows

package windowsaccount

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func verifySharedParent(h windows.Handle) error {
	if immutableHandle(h, "S-1-5-32-545", true, false) != nil {
		return ErrPlan
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrPlan
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || owner.String() != "S-1-5-18" {
		return ErrPlan
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 3 {
		return ErrPlan
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrPlan
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if seen[sid] {
			return ErrPlan
		}
		seen[sid] = true
		switch sid {
		case "S-1-5-18", "S-1-5-32-544":
			if uint32(ace.Mask) != (windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff) || ace.Header.AceFlags != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
				return ErrPlan
			}
		case "S-1-5-32-545":
			if uint32(ace.Mask) != sharedParentMetadataMask || ace.Header.AceFlags != 0 {
				return ErrPlan
			}
		default:
			return ErrPlan
		}
	}
	return nil
}
