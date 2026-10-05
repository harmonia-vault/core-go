//go:build windows

package windowsservice

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LockedConfig 固定经过 ACL 检查的二进制/config 与目录句柄；停止前不允许覆盖/换路径。
type LockedConfig struct {
	Config  Config
	handles []windows.Handle
}

func (l *LockedConfig) Close() error {
	var out error
	for len(l.handles) > 0 {
		h := l.handles[len(l.handles)-1]
		if e := windows.CloseHandle(h); e != nil {
			return e
		}
		l.handles = l.handles[:len(l.handles)-1]
	}
	return out
}

// 只评估当前对象的有效 ACE；inherit-only 不授予当前对象能力。
func checkedACL(sd *windows.SECURITY_DESCRIPTOR, readers map[string]bool, requireProtected bool, extra uint32) error {
	owner, _, e := sd.Owner()
	if e != nil || owner == nil {
		return ErrConfiguration
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if ti, _, _, e := windows.LookupSID("", `NT SERVICE\TrustedInstaller`); e == nil {
		trusted[ti.String()] = true
	}
	if !trusted[owner.String()] {
		return ErrConfiguration
	}
	control, _, e := sd.Control()
	if e != nil || (requireProtected && control&windows.SE_DACL_PROTECTED == 0) {
		return ErrConfiguration
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 {
		return ErrConfiguration
	}
	const readOnly = windows.GENERIC_READ | windows.GENERIC_EXECUTE | windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.FILE_READ_ATTRIBUTES | windows.FILE_EXECUTE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrConfiguration
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !trusted[sid] && ((readers != nil && !readers[sid]) || uint32(ace.Mask) & ^(uint32(readOnly)|extra) != 0) {
			return ErrConfiguration
		}
	}
	return nil
}
func immutableACL(sd *windows.SECURITY_DESCRIPTOR, readers map[string]bool) error {
	return checkedACL(sd, readers, true, 0)
}
func ancestorACL(sd *windows.SECURITY_DESCRIPTOR) error {
	// FILE_ADD_SUBDIRECTORY=0x4 只允许创建其它名字；禁止 DELETE_CHILD/DELETE、write attributes/EA、DAC/owner。
	// 每个已存在的下一层目录仍必须受信所有者、无 reparse，并以不共享 DELETE 的句柄固定。
	return checkedACL(sd, nil, false, 0x4)
}
func schedulerTopACL(sd *windows.SECURITY_DESCRIPTOR) error {
	// Scheduler 顶层允许默认创建相关位 0x116；其 COM 接口不由这些位授予子项删除/改 DACL 能力。
	// 仍拒绝 DELETE_CHILD/DELETE、WRITE_DAC/WRITE_OWNER、GENERIC_WRITE/ALL；子 folder 自身必须 immutable。
	return checkedACL(sd, nil, false, 0x116)
}
func pathACL(h windows.Handle, readers map[string]bool, leaf bool) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_ENCRYPTED != 0 {
		return ErrConfiguration
	}
	if leaf && (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1) {
		return ErrConfiguration
	}
	if !leaf && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrConfiguration
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrConfiguration
	}
	if !leaf {
		return ancestorACL(sd)
	}
	return immutableACL(sd, readers)
}
func pinFile(path string, readers map[string]bool, lock *LockedConfig) (windows.Handle, error) {
	if !windowsPath(path) {
		return 0, ErrConfiguration
	}
	current := filepath.VolumeName(path) + `\`
	parts := strings.Split(strings.TrimPrefix(path, current), `\`)
	for i := 0; i < len(parts); i++ {
		h, e := windows.CreateFile(windows.StringToUTF16Ptr(current), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return 0, ErrConfiguration
		}
		lock.handles = append(lock.handles, h)
		if e = pathACL(h, readers, false); e != nil {
			return 0, e
		}
		current = filepath.Join(current, parts[i])
	}

	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return 0, ErrConfiguration
	}
	lock.handles = append(lock.handles, h)
	if e = pathACL(h, readers, true); e != nil {
		return 0, e
	}
	return h, nil
}
func LoadConfig(path string) (*LockedConfig, error) {
	if !windowsPath(path) {
		return nil, ErrConfiguration
	}
	lock := &LockedConfig{}
	good := false
	defer func() {
		if !good {
			_ = lock.Close()
		}
	}()
	// 配置尚未解析前，只有原生 service/user SID 可作为只读 ACE；仍不能写。
	readers := map[string]bool{}
	// 初次 metadata 允许读取配置，而其 ACL reader 必须在 Decode 后精确复验；没有 mutation。
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, ErrConfiguration
	}
	if e = pathACL(h, nil, true); e != nil {
		_ = windows.CloseHandle(h)
		return nil, e
	}
	file := os.NewFile(uintptr(h), "profile-config")
	if file == nil {
		_ = windows.CloseHandle(h)
		return nil, ErrConfiguration
	}
	data, e := io.ReadAll(io.LimitReader(file, 8193))
	closeErr := file.Close()
	if e != nil || closeErr != nil {
		return nil, ErrConfiguration
	}
	c, e := DecodeConfig(data)
	if e != nil || !strings.EqualFold(c.ConfigurationFile, path) {
		return nil, ErrConfiguration
	}
	for _, sid := range []string{c.TargetSID, c.SyncServiceSID} {
		readers[sid] = true
	}
	for name, want := range map[string]string{c.SyncServiceName(): c.SyncServiceSID, c.BrokerServiceName(): c.BrokerServiceSID} {
		got, _, _, e := windows.LookupSID("", `NT SERVICE\`+name)
		if e != nil || got.String() != want {
			return nil, ErrConfiguration
		}
	}
	pinned, e := pinFile(path, readers, lock)
	if e != nil {
		return nil, e
	}
	// 关闭初始读取句柄后重新固定并重读，阻止检查前文件替换造成 TOCTOU。
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(pinned, &info) != nil || info.FileSizeHigh != 0 || info.FileSizeLow > 8192 {
		return nil, ErrConfiguration
	}
	var again [8193]byte
	var n uint32
	if windows.ReadFile(pinned, again[:], &n, nil) != nil {
		return nil, ErrConfiguration
	}
	exact, e := DecodeConfig(again[:n])
	if e != nil || exact != c {
		return nil, ErrConfiguration
	}
	if _, e = pinFile(c.Executable, readers, lock); e != nil {
		return nil, e
	}
	if _, e = pinFile(c.SyncExecutable, readers, lock); e != nil {
		return nil, e
	}
	lock.Config = c
	good = true
	return lock, nil
}
