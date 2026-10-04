//go:build windows

package windowsaccount

import (
	"golang.org/x/sys/windows"
	"sort"
	"strings"
	"unsafe"
)

type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}
type lsaObject struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var lsaOpen = advapi.NewProc("LsaOpenPolicy")
var lsaClose = advapi.NewProc("LsaClose")
var lsaEnum = advapi.NewProc("LsaEnumerateAccountRights")
var lsaAdd = advapi.NewProc("LsaAddAccountRights")
var lsaRemove = advapi.NewProc("LsaRemoveAccountRights")
var lsaFree = advapi.NewProc("LsaFreeMemory")

func withPolicy(write bool, f func(uintptr) error) error {
	access := uintptr(0x800)
	if write {
		access |= 0x10
	}
	attr := lsaObject{Length: uint32(unsafe.Sizeof(lsaObject{}))}
	var handle uintptr
	status, _, _ := lsaOpen.Call(0, uintptr(unsafe.Pointer(&attr)), access, uintptr(unsafe.Pointer(&handle)))
	if status != 0 {
		return ErrIdentity
	}
	defer lsaClose.Call(handle)
	return f(handle)
}
func directRights(sid string) ([]string, error) {
	var values []string
	err := withPolicy(false, func(handle uintptr) error {
		target, e := windows.StringToSid(sid)
		if e != nil {
			return ErrIdentity
		}
		var memory *lsaString
		var count uint32
		code, _, _ := lsaEnum.Call(handle, uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(&memory)), uintptr(unsafe.Pointer(&count)))
		if uint32(code) == 0xc0000034 {
			return nil
		}
		if code != 0 {
			return ErrIdentity
		}
		defer lsaFree.Call(uintptr(unsafe.Pointer(memory)))
		if count > 1024 || count > 0 && memory == nil {
			return ErrIdentity
		}
		for _, v := range unsafe.Slice(memory, int(count)) {
			if v.Length%2 != 0 || v.Length > 512 || v.Length > v.MaximumLength || v.Length > 0 && v.Buffer == nil {
				return ErrIdentity
			}
			values = append(values, windows.UTF16ToString(unsafe.Slice(v.Buffer, int(v.Length/2))))
		}
		sort.Strings(values)
		return nil
	})
	return values, err
}
func changeServiceRight(sid string, remove bool) error {
	return withPolicy(!remove, func(handle uintptr) error {
		target, e := windows.StringToSid(sid)
		if e != nil {
			return ErrIdentity
		}
		b := windows.StringToUTF16(ServiceLogonRight)
		right := lsaString{Length: uint16((len(b) - 1) * 2), MaximumLength: uint16(len(b) * 2), Buffer: &b[0]}
		var code uintptr
		if remove {
			code, _, _ = lsaRemove.Call(handle, uintptr(unsafe.Pointer(target)), 0, uintptr(unsafe.Pointer(&right)), 1)
		} else {
			code, _, _ = lsaAdd.Call(handle, uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(&right)), 1)
		}
		if code != 0 {
			return ErrUncertain
		}
		return nil
	})
}
func hasRight(rights []string, name string) bool {
	for _, r := range rights {
		if r == name {
			return true
		}
	}
	return false
}

// effectiveServiceRights只处理明确的本地SAM普通账号，包含间接本地组和公共登录组。
// 读取失败或任何Deny都保持关闭；不删除Deny，不改域/GPO。
func effectiveServiceRights(p Plan) (direct []string, allow, deny bool, err error) {
	if p.Validate() != nil {
		return nil, false, false, ErrPlan
	}
	if verifyLocalPlanAccount(p) != nil {
		return nil, false, false, ErrIdentity
	}
	direct, err = directRights(p.TargetSID)
	if err != nil {
		return
	}
	sids := []string{p.TargetSID, "S-1-1-0", "S-1-5-11", "S-1-5-6", "S-1-5-113", "S-1-2-0"}
	netapi := windows.NewLazySystemDLL("netapi32.dll")
	get := netapi.NewProc("NetUserGetLocalGroups")
	free := netapi.NewProc("NetApiBufferFree")
	var buffer **uint16
	var read, total uint32
	result, _, _ := get.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(p.LocalUser))), 0, 1, uintptr(unsafe.Pointer(&buffer)), 0xffffffff, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if result != 0 {
		return nil, false, false, ErrIdentity
	}
	defer free.Call(uintptr(unsafe.Pointer(buffer)))
	if read != total || read > 1024 || read > 0 && buffer == nil {
		return nil, false, false, ErrIdentity
	}
	for _, name := range unsafe.Slice(buffer, int(read)) {
		if name == nil {
			return nil, false, false, ErrIdentity
		}
		group := windows.UTF16PtrToString(name)
		if group == "" || strings.ContainsAny(group, "\x00\r\n") {
			return nil, false, false, ErrIdentity
		}
		sid, _, kind, e := windows.LookupSID("", group)
		if e != nil || (kind != windows.SidTypeAlias && kind != windows.SidTypeGroup) {
			return nil, false, false, ErrIdentity
		}
		if sid.String() == "S-1-5-32-544" {
			return nil, false, false, ErrIdentity
		}
		sids = append(sids, sid.String())
	}
	for _, sid := range sids {
		r, e := directRights(sid)
		if e != nil {
			return nil, false, false, e
		}
		allow = allow || hasRight(r, ServiceLogonRight)
		deny = deny || hasRight(r, DenyServiceLogonRight)
	}
	return direct, allow, deny, nil
}
