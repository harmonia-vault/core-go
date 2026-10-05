//go:build windows

package windowsservice

import (
	"github.com/harmonia-vault/core-go/internal/wincom"
	"golang.org/x/sys/windows"
	"testing"
)

func TestNativeSchedulerRootReadOnly(t *testing.T) {
	scheduler, e := wincom.Open()
	if e != nil {
		t.Fatal("native COM open failed")
	}
	defer scheduler.Close()
	top, e := scheduler.Object(scheduler.Root, "GetFolder", `\`)
	if e != nil {
		t.Fatal("native COM root failed")
	}
	value, e := scheduler.String(top, "GetSecurityDescriptor", 7)
	if e != nil {
		t.Fatal("native COM metadata failed")
	}
	sd, e := windows.SecurityDescriptorFromString(value)
	if e != nil || schedulerTopACL(sd) != nil {
		t.Fatal("native scheduler root replacement policy rejected")
	}
}
