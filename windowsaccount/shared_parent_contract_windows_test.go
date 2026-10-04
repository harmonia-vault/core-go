//go:build windows

package windowsaccount

import (
	"testing"

	"github.com/harmonia-vault/core-go/internal/windowsacltest"
	"golang.org/x/sys/windows"
)

func TestSharedParentMetadataDoesNotGrantChildAccess(t *testing.T) {
	const target = "S-1-5-21-11-22-33-1001"
	const other = "S-1-5-21-11-22-33-1002"
	parent, e := windows.SecurityDescriptorFromString(sharedParentDirectory)
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := parent.DACL()
	if e != nil || acl == nil || acl.AceCount != 3 {
		t.Fatal("parent ACL shape")
	}
	var users *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 2, &users) != nil || uint32(users.Mask) != sharedParentMetadataMask || users.Header.AceFlags != 0 {
		t.Fatal("BU access must be exact and non-inheriting")
	}
	if !windowsacltest.Allows(t, parent, other, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE) {
		t.Fatal("ordinary BU metadata access denied")
	}
	for _, mask := range []uint32{windows.FILE_LIST_DIRECTORY, windows.FILE_READ_DATA, windows.FILE_WRITE_DATA, windows.FILE_APPEND_DATA, windows.WRITE_DAC, windows.WRITE_OWNER, windows.DELETE} {
		if windowsacltest.Allows(t, parent, other, mask) {
			t.Fatal("public parent granted list/content/write/control access")
		}
	}
	for _, descriptor := range []string{ownedDirectoryDescriptor(target, false), ownedDirectoryDescriptor(target, true)} {
		child, e := windows.SecurityDescriptorFromString(descriptor)
		if e != nil {
			t.Fatal(e)
		}
		control, _, e := child.Control()
		if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("instance inherited shared-parent access")
		}
		if !windowsacltest.Allows(t, child, target, windows.FILE_READ_DATA) || windowsacltest.Allows(t, child, other, windows.FILE_READ_DATA) || windowsacltest.Allows(t, child, other, windows.READ_CONTROL) {
			t.Fatal("per-user instance isolation failed")
		}
	}
}
