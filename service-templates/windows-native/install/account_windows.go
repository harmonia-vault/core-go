//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"runtime"
	"unsafe"
)

var netAPI = windows.NewLazySystemDLL("netapi32.dll")
var userAdd = netAPI.NewProc("NetUserAdd")
var userDel = netAPI.NewProc("NetUserDel")
var groupAdd = netAPI.NewProc("NetLocalGroupAddMembers")
var userenv = windows.NewLazySystemDLL("userenv.dll")
var createProfile = userenv.NewProc("CreateProfile")
var deleteProfile = userenv.NewProc("DeleteProfileW")
var logon = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
var lsaOpen = windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaOpenPolicy")
var lsaAdd = windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaAddAccountRights")
var lsaRemove = windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaRemoveAccountRights")
var lsaClose = windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaClose")

// Microsoft USER_INFO_1/LOCALGROUP_MEMBERS_INFO_0/LSA_OBJECT_ATTRIBUTES/LSA_UNICODE_STRING 公开布局。
type userInfo1 struct {
	Name, Password *uint16
	Age, Privilege uint32
	Home, Comment  *uint16
	Flags          uint32
	Script         *uint16
}
type lsaAttributes struct {
	Length     uint32
	Root, Name uintptr
	Attributes uint32
	SD, QOS    uintptr
}
type lsaUnicode struct {
	Length, Maximum uint16
	Buffer          *uint16
}

func accountSID(name string) (string, error) {
	computer, e := windows.ComputerName()
	if e != nil {
		return "", rejected
	}
	sid, _, kind, e := windows.LookupSID("", computer+`\`+name)
	if e != nil || kind != windows.SidTypeUser {
		return "", rejected
	}
	return sid.String(), nil
}
func randomPassword() ([]uint16, error) {
	seed := make([]byte, 64)
	defer clear(seed)
	if _, e := rand.Read(seed); e != nil {
		return nil, rejected
	}
	enc := make([]byte, base64.RawURLEncoding.EncodedLen(len(seed)))
	defer clear(enc)
	base64.RawURLEncoding.Encode(enc, seed)
	pw := make([]uint16, len(enc)+5)
	for i, c := range enc {
		pw[i] = uint16(c)
	}
	copy(pw[len(enc):], []uint16{'a', 'A', '1', '!', 0})
	return pw, nil
}
func addAccount(name string, pw []uint16) error {
	info := userInfo1{Name: windows.StringToUTF16Ptr(name), Password: &pw[0], Privilege: 1, Comment: windows.StringToUTF16Ptr("Harmonia synthetic native lab"), Flags: 0x200 | 0x1 | 0x10000 | 0x40}
	var parameter uint32
	result, _, _ := userAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(pw)
	if result != 0 {
		return rejected
	}
	return nil
}
func joinUsers(sidText string) error {
	group, e := windows.StringToSid("S-1-5-32-545")
	if e != nil {
		return rejected
	}
	name, _, _, e := group.LookupAccount("")
	if e != nil {
		return rejected
	}
	sid, e := windows.StringToSid(sidText)
	if e != nil {
		return rejected
	}
	entry := struct{ SID *windows.SID }{sid}
	result, _, _ := groupAdd.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, uintptr(unsafe.Pointer(&entry)), 1)
	if result != 0 {
		return rejected
	}
	return nil
}
func freshProfile(sid, name string, m *manifest) error {
	var path [260]uint16
	result, _, _ := createProfile.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(sid))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	code := uint32(result)
	m.ProfileHRESULT = &code
	if m.save() != nil {
		return rejected
	}
	if code != 0 {
		fmt.Fprintf(os.Stderr, "PROFILE_CREATE_HRESULT=0x%08x\n", code)
		return rejected
	}
	return nil
}

// 字节长度不含 NUL，Maximum 是实际 UTF16 buffer 字节数；固定 grant caller 不接收外部 right 名。
func encodedRightName(name string) (lsaUnicode, []uint16, error) {
	units, e := windows.UTF16FromString(name)
	if e != nil || len(units) < 2 || len(units) > 32767 {
		return lsaUnicode{}, nil, rejected
	}
	return lsaUnicode{Length: uint16((len(units) - 1) * 2), Maximum: uint16(len(units) * 2), Buffer: &units[0]}, units, nil
}
func recordBatchStatus(m *manifest, stage string, raw uintptr) error {
	value := uint32(raw)
	m.BatchNTSTATUS = &value
	m.BatchStatusStage = stage
	if m.save() != nil {
		return rejected
	}
	if value != 0 {
		fmt.Fprintf(os.Stderr, "BATCH_NTSTATUS stage=%s value=0x%08x\n", stage, value)
	}
	return nil
}
func batchRight(sidText string, remove bool, m *manifest) error {
	sid, e := windows.StringToSid(sidText)
	if e != nil {
		return rejected
	}
	a := lsaAttributes{Length: uint32(unsafe.Sizeof(lsaAttributes{}))}
	var policy windows.Handle
	result, _, _ := lsaOpen.Call(0, uintptr(unsafe.Pointer(&a)), 0x810, uintptr(unsafe.Pointer(&policy)))
	if uint32(result) == 0 {
		defer lsaClose.Call(uintptr(policy))
	}
	if recordBatchStatus(m, "lsa-open", result) != nil || uint32(result) != 0 {
		return rejected
	}
	right, units, e := encodedRightName("SeBatchLogonRight")
	if e != nil {
		return e
	}
	if remove {
		result, _, _ = lsaRemove.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&right)), 1)
	} else {
		result, _, _ = lsaAdd.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&right)), 1)
	}
	runtime.KeepAlive(units)
	stage := "lsa-add"
	if remove {
		stage = "lsa-remove"
	}
	if recordBatchStatus(m, stage, result) != nil || uint32(result) != 0 {
		return rejected
	}
	return nil
}
func selfRegister(m *manifest, pw []uint16) error {
	var token windows.Token
	result, _, _ := logon.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(m.AccountName))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("."))), uintptr(unsafe.Pointer(&pw[0])), 4, 0, uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(pw)
	if result == 0 {
		return rejected
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil || u.User.Sid.String() != m.TargetSID {
		return rejected
	}
	c := m.config()
	command := windows.StringToUTF16Ptr(`"` + c.Executable + `" self-register --config "` + c.ConfigurationFile + `"`)
	// 仅固定公开系统路径；不继承/扫描任何真实环境。
	env := []uint16{}
	for _, entry := range []string{`Path=C:\Windows\System32`, `SystemDrive=C:`, `SystemRoot=C:\Windows`, `TEMP=C:\Windows\Temp`, `TMP=C:\Windows\Temp`} {
		v, _ := windows.UTF16FromString(entry)
		env = append(env, v...)
	}
	env = append(env, 0)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(c.Executable), command, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, &env[0], windows.StringToUTF16Ptr(m.Install), &si, &pi) != nil {
		return rejected
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	wait, e := windows.WaitForSingleObject(pi.Process, 25000)
	if e != nil || wait != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 2)
		_, _ = windows.WaitForSingleObject(pi.Process, 5000)
		return rejected
	}
	var code uint32
	if windows.GetExitCodeProcess(pi.Process, &code) != nil || code != 0 {
		return rejected
	}
	return nil
}
func removeAccount(m *manifest) error {
	if m.BatchGranted {
		if m.begin("batch-remove") != nil {
			return rejected
		}
		if batchRight(m.TargetSID, true, m) != nil {
			return rejected
		}
		m.BatchGranted = false
		if m.committed() != nil {
			return rejected
		}
	}
	if m.ProfileCreated {
		if m.begin("profile-delete") != nil {
			return rejected
		}
		result, _, _ := deleteProfile.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(m.TargetSID))), 0, 0)
		if result == 0 {
			return rejected
		}
		m.ProfileCreated = false
		if m.committed() != nil {
			return rejected
		}
	}
	if m.AccountCreated {
		sid, e := accountSID(m.AccountName)
		if e != nil || sid != m.TargetSID {
			return rejected
		}
		if m.begin("account-delete") != nil {
			return rejected
		}
		result, _, _ := userDel.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(m.AccountName))))
		if result != 0 {
			return rejected
		}
		m.AccountCreated = false
		if m.committed() != nil {
			return rejected
		}
	}
	return nil
}

// resolveProfileAbsent 仅本次 profile-create 未知阶段：重新查 exact SID/两个真实 NOT_FOUND，保存失败历史后才解除清理门槛。
// 不创建 profile、不授权限、不尝试重置密码或继续 provisioning。
func resolveProfileAbsent(m *manifest, expectedSID string) error {
	if m.PendingAction != "profile-create" || m.TargetSID != expectedSID || !m.AccountCreated || m.ProfileCreated || m.BatchGranted || m.RootCreated || m.FolderCreated || m.TaskRegistered || len(m.Services) != 0 || m.TaskFolder != "" {
		return rejected
	}
	sid, e := accountSID(m.AccountName)
	if e != nil || sid != expectedSID {
		return rejected
	}
	key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+expectedSID, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e == nil {
		key.Close()
		return rejected
	}
	if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return rejected
	}
	_, e = windows.GetFileAttributes(windows.StringToUTF16Ptr(`C:\Users\` + m.AccountName))
	if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
		return rejected
	}
	m.FailureHistory = append(m.FailureHistory, profileFailure{Stage: "profile-create", Outcome: "confirmed-not-created", HRESULTRecorded: m.ProfileHRESULT != nil, HRESULT: m.ProfileHRESULT, ProfileListCode: 2, DirectoryCode: 2})
	m.Phase = "profile-create-confirmed-not-created"
	return m.committed()
}

// 只读确认本次新 SID 没有任何 direct right；不能仅依赖 manifest Batch=false。
func directRightsAbsent(sidText string) error {
	sid, e := windows.StringToSid(sidText)
	if e != nil {
		return rejected
	}
	a := lsaAttributes{Length: uint32(unsafe.Sizeof(lsaAttributes{}))}
	var policy windows.Handle
	status, _, _ := lsaOpen.Call(0, uintptr(unsafe.Pointer(&a)), 0x800, uintptr(unsafe.Pointer(&policy)))
	if uint32(status) != 0 {
		return rejected
	}
	defer lsaClose.Call(uintptr(policy))
	enum := windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaEnumerateAccountRights")
	free := windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaFreeMemory")
	var rights *lsaUnicode
	var count uint32
	status, _, _ = enum.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rights)), uintptr(unsafe.Pointer(&count)))
	if rights != nil {
		defer free.Call(uintptr(unsafe.Pointer(rights)))
	}
	if uint32(status) != 0 || count != 0 {
		return rejected
	}
	return nil
}
func resolveBatchAbsent(m *manifest, expectedSID string) error {
	if m.PendingAction != "batch-add" || m.TargetSID != expectedSID || !m.AccountCreated || !m.ProfileCreated || m.ProfileHRESULT == nil || *m.ProfileHRESULT != 0 || m.BatchGranted || m.RootCreated || m.FolderCreated || m.TaskRegistered || len(m.Services) != 0 || m.TaskFolder != "" {
		return rejected
	}
	sid, e := accountSID(m.AccountName)
	if e != nil || sid != expectedSID {
		return rejected
	}
	key, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+expectedSID, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return rejected
	}
	defer key.Close()
	path, _, e := key.GetStringValue("ProfileImagePath")
	if e != nil || path != `C:\Users\`+m.AccountName {
		return rejected
	}
	attrs, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if e != nil || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return rejected
	}
	if directRightsAbsent(expectedSID) != nil {
		return rejected
	}
	m.BatchFailureHistory = append(m.BatchFailureHistory, batchFailure{Stage: "batch-add", Outcome: "confirmed-no-direct-rights", NTSTATUSRecorded: m.BatchNTSTATUS != nil, NTSTATUS: m.BatchNTSTATUS, NTSTATUSStage: m.BatchStatusStage, EnumerationStatus: 0, DirectRightCount: 0})
	m.Phase = "batch-add-confirmed-no-direct-rights"
	return m.committed()
}
