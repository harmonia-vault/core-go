//go:build windows

package windowsaccount

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func serviceConfigValue(handle windows.Handle, level uint32) ([]byte, error) {
	var needed uint32
	if e := windows.QueryServiceConfig2(handle, level, nil, 0, &needed); e != windows.ERROR_INSUFFICIENT_BUFFER || needed < 4 || needed > 8192 {
		return nil, ErrIdentity
	}
	data := make([]byte, needed)
	if windows.QueryServiceConfig2(handle, level, &data[0], uint32(len(data)), &needed) != nil || needed > uint32(len(data)) {
		return nil, ErrIdentity
	}
	return data, nil
}

// 不把配置写入成功当作权限实际生效。每次服务操作回读身份组、权限和精确DACL。
func verifyServiceConfiguration(handle windows.Handle, target string) error {
	sid, e := serviceConfigValue(handle, windows.SERVICE_CONFIG_SERVICE_SID_INFO)
	if e != nil || *(*uint32)(unsafe.Pointer(&sid[0])) != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		return ErrIdentity
	}
	privileges, e := serviceConfigValue(handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO)
	if e != nil || len(privileges) < int(unsafe.Sizeof(uintptr(0))) {
		return ErrIdentity
	}
	names := *(**uint16)(unsafe.Pointer(&privileges[0]))
	base, address := uintptr(unsafe.Pointer(&privileges[0])), uintptr(unsafe.Pointer(names))
	expected := append(windows.StringToUTF16("SeChangeNotifyPrivilege"), 0)
	// 原生API返回的LPWSTR必须位于回读buffer内部；在此边界内读取单一MULTI_SZ。
	if address < base+unsafe.Sizeof(uintptr(0)) || address%2 != 0 || address-base > uintptr(len(privileges)) || uintptr(len(expected)*2) > uintptr(len(privileges))-(address-base) {
		return ErrIdentity
	}
	for i, unit := range unsafe.Slice(names, len(expected)) {
		if unit != expected[i] {
			return ErrIdentity
		}
	}
	sd, e := windows.GetSecurityInfo(handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrIdentity
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount != 3 {
		return ErrIdentity
	}
	expectedACL := map[string]uint32{"S-1-5-18": 0xf01ff, "S-1-5-32-544": 0xf01ff, target: 0x20005}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return ErrIdentity
		}
		name := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		want, ok := expectedACL[name]
		if !ok || uint32(ace.Mask) != want {
			return ErrIdentity
		}
		delete(expectedACL, name)
	}
	if len(expectedACL) != 0 {
		return ErrIdentity
	}
	return nil
}
