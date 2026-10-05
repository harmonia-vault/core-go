//go:build windows

package windowsservice

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

type ownedPrivileges struct {
	Count  uint32
	Values [3]windows.LUIDAndAttributes
}

// 仅启用本 SYSTEM token 已拥有的权限，恢复原 flags；不调用 LsaAddAccountRights。
func enableOwnedPrivileges() (func() error, error) {
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token) != nil {
		return nil, ErrIdentity
	}
	closeError := func(e error) (func() error, error) { _ = token.Close(); return nil, e }
	var available struct {
		Count  uint32
		Values [128]windows.LUIDAndAttributes
	}
	var size uint32
	if windows.GetTokenInformation(token, windows.TokenPrivileges, (*byte)(unsafe.Pointer(&available)), uint32(unsafe.Sizeof(available)), &size) != nil || available.Count > 128 || size < 4+available.Count*uint32(unsafe.Sizeof(available.Values[0])) {
		return closeError(ErrIdentity)
	}
	desired := ownedPrivileges{Count: 3}
	previous := ownedPrivileges{Count: 3}
	for i, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege"} {
		var luid windows.LUID
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid) != nil {
			return closeError(ErrIdentity)
		}
		found := false
		for _, item := range available.Values[:available.Count] {
			if item.Luid == luid && item.Attributes&windows.SE_PRIVILEGE_REMOVED == 0 {
				found = true
				previous.Values[i] = item
				desired.Values[i] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
				break
			}
		}
		if !found {
			return closeError(ErrIdentity)
		}
	}
	if windows.AdjustTokenPrivileges(token, false, (*windows.Tokenprivileges)(unsafe.Pointer(&desired)), 0, nil, nil) != nil {
		return closeError(ErrIdentity)
	}
	return func() error {
		e := windows.AdjustTokenPrivileges(token, false, (*windows.Tokenprivileges)(unsafe.Pointer(&previous)), 0, nil, nil)
		ce := token.Close()
		if e != nil {
			return e
		}
		return ce
	}, nil
}
