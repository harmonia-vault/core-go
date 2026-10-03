//go:build windows

package platform

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// 结构布局来自 Microsoft PROFILEINFOW；不用未声明的私有 profile API。
type windowsProfileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

var profileUserenv = windows.NewLazySystemDLL("userenv.dll")
var loadWindowsProfile = profileUserenv.NewProc("LoadUserProfileW")
var unloadWindowsProfile = profileUserenv.NewProc("UnloadUserProfile")

type windowsProfileBackend struct {
	sid         string
	account     string
	directory   string
	token       windows.Token
	profile     windows.Handle
	profileList registry.Key
	directories []windows.Handle
	allowed     map[string]bool
}

// USER_INFO_3 的公开布局；只检查已有本地账号的 profile 配置，密码字段必须为 API 规定的 NULL。
type localProfileUserInfo struct {
	Name             *uint16
	Password         *uint16
	PasswordAge      uint32
	Privilege        uint32
	HomeDirectory    *uint16
	Comment          *uint16
	Flags            uint32
	ScriptPath       *uint16
	AuthFlags        uint32
	FullName         *uint16
	UserComment      *uint16
	Parameters       *uint16
	Workstations     *uint16
	LastLogon        uint32
	LastLogoff       uint32
	AccountExpires   uint32
	MaxStorage       uint32
	UnitsPerWeek     uint32
	LogonHours       *byte
	BadPasswordCount uint32
	LogonCount       uint32
	LogonServer      *uint16
	CountryCode      uint32
	CodePage         uint32
	UserID           uint32
	PrimaryGroupID   uint32
	Profile          *uint16
	HomeDrive        *uint16
	PasswordExpired  uint32
}

func existingLocalProfileAccount(account, sid string) error {
	computer, err := windows.ComputerName()
	if err != nil {
		return ErrProfileIdentity
	}
	actual, _, kind, err := windows.LookupSID("", computer+`\`+account)
	if err != nil || kind != windows.SidTypeUser || actual.String() != sid {
		return ErrProfileIdentity
	}
	var buffer *byte
	if err := windows.NetUserGetInfo(nil, windows.StringToUTF16Ptr(account), 3, &buffer); err != nil {
		return ErrProfileIdentity
	}
	defer windows.NetApiBufferFree(buffer)
	if buffer == nil {
		return ErrProfileIdentity
	}
	info := (*localProfileUserInfo)(unsafe.Pointer(buffer))
	// USER_INFO_3.profile 非空说明配置了漫游 profile；此窄适配器拒绝，不回退本地副本。
	if info.Password != nil || (info.Profile != nil && *info.Profile != 0) {
		return ErrProfileIdentity
	}
	return nil
}

// NewWindowsProfileEnvironment 创建后续 broker 可持有的 Environment store。
// trustedToken 必须由可信 owner 预先取得；本函数不登录、不取得 token、不提权/授予权限。
// 当前正式 daemon 未接入此 API；无登录 token provider、broker 鉴权和原生验收仍有 gate。
func NewWindowsProfileEnvironment(targetSID string, trustedToken windows.Token) (*ProfileEnvironmentStore, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ValidSID(targetSID) || trustedToken == 0 {
		return nil, ErrProfileIdentity
	}
	if err := requireProfileProcess(); err != nil {
		return nil, err
	}
	user, err := trustedToken.GetTokenUser()
	if err != nil || user.User.Sid.String() != targetSID {
		return nil, ErrProfileIdentity
	}
	var tokenType uint32
	var size uint32
	if err := windows.GetTokenInformation(trustedToken, windows.TokenType, (*byte)(unsafe.Pointer(&tokenType)), 4, &size); err != nil {
		return nil, err
	}
	if tokenType == windows.TokenImpersonation {
		var level uint32
		if err := windows.GetTokenInformation(trustedToken, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &size); err != nil {
			return nil, err
		}
		if level < windows.SecurityImpersonation {
			return nil, ErrProfileIdentity
		}
	} else if tokenType != windows.TokenPrimary {
		return nil, ErrProfileIdentity
	}
	sid, err := windows.StringToSid(targetSID)
	if err != nil {
		return nil, ErrProfileIdentity
	}
	account, domain, kind, err := sid.LookupAccount("")
	computer, computerErr := windows.ComputerName()
	if err != nil || computerErr != nil || kind != windows.SidTypeUser || !strings.EqualFold(domain, computer) || account == "" || strings.ContainsAny(account, "\\/\x00") {
		return nil, ErrProfileIdentity
	}
	roundTrip, _, roundType, err := windows.LookupSID("", computer+`\`+account)
	if err != nil || roundType != windows.SidTypeUser || roundTrip.String() != targetSID {
		return nil, ErrProfileIdentity
	}
	if err := existingLocalProfileAccount(account, targetSID); err != nil {
		return nil, err
	}
	b := &windowsProfileBackend{sid: targetSID, account: account, allowed: map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}}
	if ti, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`); err == nil {
		b.allowed[ti.String()] = true
	}
	// 复制的是调用方已经持有的 token，不创建新登录；不要求 TOKEN_ASSIGN_PRIMARY/ADJUST_PRIVILEGES。
	if err := windows.DuplicateTokenEx(trustedToken, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, nil, windows.SecurityImpersonation, windows.TokenPrimary, &b.token); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = b.Close()
		}
	}()
	duplicated, err := b.token.GetTokenUser()
	if err != nil || duplicated.User.Sid.String() != targetSID {
		return nil, ErrProfileIdentity
	}
	b.directory, err = b.token.GetUserProfileDirectory()
	if err != nil || !profileLocalPath(b.directory) || filepath.Clean(b.directory) != b.directory {
		return nil, ErrProfileIdentity
	}
	const profileListPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	parent, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListPath, registry.QUERY_VALUE|windows.READ_CONTROL|registry.WOW64_64KEY)
	if err != nil {
		return nil, ErrProfileIdentity
	}
	err = b.validateSecurity(windows.Handle(parent), windows.SE_REGISTRY_KEY, false, false)
	_ = parent.Close()
	if err != nil {
		return nil, err
	}
	b.profileList, err = registry.OpenKey(registry.LOCAL_MACHINE, profileListPath+`\`+targetSID, registry.QUERY_VALUE|windows.READ_CONTROL|registry.WOW64_64KEY)
	if err != nil {
		return nil, ErrProfileIdentity
	}
	if err := b.validateProfileList(); err != nil {
		return nil, err
	}
	current := filepath.VolumeName(b.directory) + `\`
	// 保持目录句柄且不共享 DELETE，避免 profile 路径在加载过程中被替换为 junction。
	for _, part := range append([]string{""}, strings.Split(b.directory[len(current):], `\`)...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		handle, err := windows.CreateFile(windows.StringToUTF16Ptr(current), windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, ErrProfileIdentity
		}
		b.directories = append(b.directories, handle)
		if err := b.validatePathHandle(handle, true); err != nil {
			return nil, err
		}
	}
	store, err := newProfileEnvironmentStore(targetSID, b)
	if err != nil {
		return nil, err
	}
	ok = true
	return store, nil
}

// 不改变 privilege：要求专用 SYSTEM owner 已显式启用所需权限，且线程没有客户端 impersonation。
func requireProfileProcess() error {
	process := windows.GetCurrentProcessToken()
	user, err := process.GetTokenUser()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return ErrProfilePrivilege
	}
	var thread windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread)
	if err == nil {
		_ = thread.Close()
		return ErrProfilePrivilege
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return ErrProfilePrivilege
	}
	var privileges struct {
		Count  uint32
		Values [128]windows.LUIDAndAttributes
	}
	var length uint32
	if err := windows.GetTokenInformation(process, windows.TokenPrivileges, (*byte)(unsafe.Pointer(&privileges)), uint32(unsafe.Sizeof(privileges)), &length); err != nil {
		return ErrProfilePrivilege
	}
	if privileges.Count > uint32(len(privileges.Values)) || length < 4+privileges.Count*uint32(unsafe.Sizeof(privileges.Values[0])) {
		return ErrProfilePrivilege
	}
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		var required windows.LUID
		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &required); err != nil {
			return ErrProfilePrivilege
		}
		enabled := false
		for _, value := range privileges.Values[:privileges.Count] {
			if value.Luid == required && value.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
				enabled = true
			}
		}
		if !enabled {
			return ErrProfilePrivilege
		}
	}
	return nil
}
func (b *windowsProfileBackend) validateSecurity(handle windows.Handle, kind windows.SE_OBJECT_TYPE, allowTarget, directory bool) error {
	sd, err := windows.GetSecurityInfo(handle, kind, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrProfileIdentity
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (!b.allowed[owner.String()] && !(allowTarget && owner.String() == b.sid)) {
		return ErrProfileIdentity
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrProfileIdentity
	}
	dangerous := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE)
	if kind == windows.SE_REGISTRY_KEY {
		dangerous |= registry.SET_VALUE | registry.CREATE_SUB_KEY | registry.CREATE_LINK
	} else {
		dangerous |= windows.FILE_WRITE_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
		if directory {
			dangerous |= 0x00000040 // FILE_DELETE_CHILD，Microsoft winnt.h。
		} else {
			dangerous |= windows.FILE_APPEND_DATA
		}
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return ErrProfileIdentity
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// 不猜条件/对象 ACE 的有效权限；当前窄适配器保守拒绝它们。
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrProfileIdentity
		}
		identity := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if uint32(ace.Mask)&dangerous != 0 && !b.allowed[identity] && !(allowTarget && identity == b.sid) {
			return ErrProfileIdentity
		}
	}
	return nil
}
func (b *windowsProfileBackend) validatePathHandle(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return ErrProfileIdentity
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		return ErrProfileIdentity
	}
	return b.validateSecurity(handle, windows.SE_FILE_OBJECT, true, directory)
}
func (b *windowsProfileBackend) validateProfileList() error {
	if err := b.validateSecurity(windows.Handle(b.profileList), windows.SE_REGISTRY_KEY, false, false); err != nil {
		return err
	}
	value, kind, err := b.profileList.GetStringValue("ProfileImagePath")
	if err != nil || (kind != registry.SZ && kind != registry.EXPAND_SZ) {
		return ErrProfileIdentity
	}
	if strings.HasPrefix(strings.ToLower(value), "%systemdrive%") {
		system, err := windows.GetWindowsDirectory()
		if err != nil {
			return ErrProfileIdentity
		}
		value = filepath.VolumeName(system) + value[len("%systemdrive%"):]
	}
	// 其他环境替换、临时/新建/漫游 profile 不作为此次既有本地 profile 的可信路径。
	if !profileLocalPath(value) || filepath.Clean(value) != value || !strings.EqualFold(value, b.directory) {
		return ErrProfileIdentity
	}
	return nil
}
func profileCallError(err error) error {
	if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
		return windows.ERROR_GEN_FAILURE
	}
	return err
}
func (b *windowsProfileBackend) Load() (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if b.token == 0 || b.profile != 0 {
		return false, ErrProfileIdentity
	}
	if err := requireProfileProcess(); err != nil {
		return false, err
	}
	if err := existingLocalProfileAccount(b.account, b.sid); err != nil {
		return false, err
	}
	if err := b.validateProfileList(); err != nil {
		return false, err
	}
	for _, handle := range b.directories {
		if err := b.validatePathHandle(handle, true); err != nil {
			return false, err
		}
	}
	// 必须已经存在真实 hive；只查身份/链接元数据，不读取 NTUSER.DAT 内容。
	hive, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(b.directory, "NTUSER.DAT")), windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, ErrProfileIdentity
	}
	defer windows.CloseHandle(hive)
	if err := b.validatePathHandle(hive, false); err != nil {
		return false, err
	}
	name, err := windows.UTF16PtrFromString(b.account)
	if err != nil {
		return false, ErrProfileIdentity
	}
	info := windowsProfileInfo{Size: uint32(unsafe.Sizeof(windowsProfileInfo{})), Flags: 1, UserName: name} // PI_NOUI
	ok, _, callErr := loadWindowsProfile.Call(uintptr(b.token), uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(name)
	if ok == 0 {
		return false, profileCallError(callErr)
	}
	b.profile = info.Profile
	if b.profile == 0 {
		return false, ErrProfileIdentity
	}
	// Load 后重新核对实际 token profile 路径与机器目录；成功加载却不满足策略时须释放已取得的引用。
	actual, err := b.token.GetUserProfileDirectory()
	if err != nil || !strings.EqualFold(actual, b.directory) {
		return true, ErrProfileIdentity
	}
	if err := b.validateProfileList(); err != nil {
		return true, err
	}
	return true, nil
}
func (b *windowsProfileBackend) OpenEnvironment() (closeableUserEnvironment, error) {
	if b.profile == 0 {
		return nil, ErrProfileIdentity
	}
	// hProfile 的 KEY_ALL_ACCESS 永不暴露；仅返回固定子 key 的 QUERY_VALUE/SET_VALUE 句柄。
	var handle windows.Handle
	const openLink = 0x00000008 // REG_OPTION_OPEN_LINK，Microsoft winnt.h。
	err := windows.RegOpenKeyEx(b.profile, windows.StringToUTF16Ptr("Environment"), openLink, registry.QUERY_VALUE|registry.SET_VALUE|windows.READ_CONTROL, &handle)
	if err != nil {
		return nil, err
	} // 不为已有 profile 自动创建/覆盖缺少的 Environment 子 key。
	key := registry.Key(handle)
	// 不跟随用户可创建的注册表链接跳到其他 hive；只在已固定句柄上读取元数据。
	_, kind, linkErr := key.GetValue("SymbolicLinkValue", nil)
	if (linkErr != nil && !errors.Is(linkErr, registry.ErrNotExist)) || (linkErr == nil && kind == registry.LINK) {
		_ = key.Close()
		return nil, ErrProfileIdentity
	}
	if err := b.validateSecurity(handle, windows.SE_REGISTRY_KEY, true, false); err != nil {
		_ = key.Close()
		return nil, err
	}
	return &registryUserStore{sid: b.sid, key: key}, nil
}
func (b *windowsProfileBackend) Unload() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if b.profile == 0 {
		return ErrProfileIdentity
	}
	if err := requireProfileProcess(); err != nil {
		return err
	}
	ok, _, callErr := unloadWindowsProfile.Call(uintptr(b.token), uintptr(b.profile))
	if ok == 0 {
		return profileCallError(callErr)
	}
	b.profile = 0 // 不 RegCloseKey hProfile，不 RegUnLoadKey 全局 HKU\SID。
	return nil
}
func (b *windowsProfileBackend) Close() error {
	if b.profile != 0 {
		return ErrProfileIdentity
	}
	for len(b.directories) != 0 {
		index := len(b.directories) - 1
		if err := windows.CloseHandle(b.directories[index]); err != nil {
			return err
		}
		b.directories = b.directories[:index]
	}
	if b.profileList != 0 {
		if err := b.profileList.Close(); err != nil {
			return err
		}
		b.profileList = 0
	}
	if b.token != 0 {
		if err := b.token.Close(); err != nil {
			return err
		}
		b.token = 0
	}
	return nil
}
