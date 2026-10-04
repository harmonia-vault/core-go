//go:build windows

package localkeys

import (
	"testing"

	"github.com/harmonia-vault/core-go/internal/windowsacltest"
	"golang.org/x/sys/windows"
)

func TestPrivateKeyDescriptorRejectsOtherBuiltinUser(t *testing.T) {
	const owner = "S-1-5-21-11-22-33-1001"
	const other = "S-1-5-21-11-22-33-1002"
	for _, directory := range []bool{false, true} {
		sd, e := privateWindowsSD(owner, directory)
		if e != nil {
			t.Fatal(e)
		}
		control, _, e := sd.Control()
		if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("private storage descriptor inherits public parent access")
		}
		if !windowsacltest.Allows(t, sd, owner, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA) {
			t.Fatal("owner cannot use private key/state")
		}
		for _, mask := range []uint32{windows.FILE_READ_DATA, windows.FILE_WRITE_DATA, windows.READ_CONTROL} {
			if windowsacltest.Allows(t, sd, other, mask) {
				t.Fatal("other Builtin User can access private key/state")
			}
		}
	}
}
