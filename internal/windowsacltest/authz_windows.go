//go:build windows

// Package windowsacltest evaluates ACLs only in user-mode synthetic Authz
// contexts. It never creates an OS token, logs on, impersonates, launches a
// process or modifies a file/ACL. It is imported only by permission tests.
package windowsacltest

import (
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type request struct {
	DesiredAccess      uint32
	PrincipalSelf      *windows.SID
	ObjectTypeList     uintptr
	ObjectTypeListSize uint32
	OptionalArguments  uintptr
}
type reply struct {
	Count   uint32
	Granted *uint32
	SACL    *uint32
	Error   *uint32
}

// Allows uses AUTHZ_SKIP_TOKEN_GROUPS=2 unconditionally. The default flags=0
// S4U/group lookup path is deliberately unavailable. BU is explicitly supplied
// as a synthetic enabled group; no real account or machine policy is inspected.
func Allows(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR, userSID string, desired uint32) bool {
	t.Helper()
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(request{}) != 40 || unsafe.Sizeof(reply{}) != 32 {
		t.Fatal("unsupported Authz contract ABI")
	}
	dll := windows.NewLazySystemDLL("authz.dll")
	var manager, base, client uintptr
	ok, _, _ := dll.NewProc("AuthzInitializeResourceManager").Call(1, 0, 0, 0, 0, uintptr(unsafe.Pointer(&manager))) // NO_AUDIT
	if ok == 0 {
		t.Fatal("Authz manager unavailable")
	}
	defer dll.NewProc("AuthzFreeResourceManager").Call(manager)
	user, e := windows.StringToSid(userSID)
	if e != nil {
		t.Fatal("synthetic SID invalid")
	}
	// LUID is a zero 64-bit by-value field on the supported Windows ARM64 ABI.
	ok, _, _ = dll.NewProc("AuthzInitializeContextFromSid").Call(2, uintptr(unsafe.Pointer(user)), manager, 0, 0, 0, uintptr(unsafe.Pointer(&base)))
	runtime.KeepAlive(user)
	if ok == 0 {
		t.Fatal("synthetic no-group-lookup context failed")
	}
	defer dll.NewProc("AuthzFreeContext").Call(base)
	users, e := windows.StringToSid("S-1-5-32-545")
	if e != nil {
		t.Fatal("BU SID invalid")
	}
	group := windows.SIDAndAttributes{Sid: users, Attributes: windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_MANDATORY}
	ok, _, _ = dll.NewProc("AuthzAddSidsToContext").Call(base, uintptr(unsafe.Pointer(&group)), 1, 0, 0, uintptr(unsafe.Pointer(&client)))
	runtime.KeepAlive(users)
	runtime.KeepAlive(group)
	if ok == 0 {
		t.Fatal("synthetic BU context failed")
	}
	defer dll.NewProc("AuthzFreeContext").Call(client)
	var granted, sacl, status uint32
	q := request{DesiredAccess: desired}
	r := reply{Count: 1, Granted: &granted, SACL: &sacl, Error: &status}
	ok, _, _ = dll.NewProc("AuthzAccessCheck").Call(0, client, uintptr(unsafe.Pointer(&q)), 0, uintptr(unsafe.Pointer(descriptor)), 0, 0, uintptr(unsafe.Pointer(&r)), 0)
	runtime.KeepAlive(descriptor)
	if ok == 0 || status != 0 && status != uint32(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("Authz bounded access evaluation failed")
	}
	return status == 0 && granted&desired == desired
}
