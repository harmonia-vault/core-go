//go:build windows

package windowsaccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"path/filepath"
	"strings"
	"unsafe"
)

type LockedConfiguration struct {
	Configuration Configuration
	handles       []windows.Handle
}

func (l *LockedConfiguration) Close() error {
	var err error
	for i := len(l.handles) - 1; i >= 0; i-- {
		err = errors.Join(err, windows.CloseHandle(l.handles[i]))
	}
	l.handles = nil
	return err
}

func immutableHandle(h windows.Handle, target string, directory, ancestor bool) error {
	return immutableHandleDetail(h, target, directory, ancestor, 0, 15)
}
func immutableHandleDetail(h windows.Handle, target string, directory, ancestor bool, resource, index uint8) error {
	fail := func(op uint8, e error) error { return configurationFailure(resource, op, index, e) }
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &info); e != nil {
		return fail(2, e)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_ENCRYPTED) != 0 || directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) || (!directory && info.NumberOfLinks != 1) {
		return fail(2, nil)
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return fail(3, e)
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return fail(4, e)
	}
	if owner == nil {
		return fail(4, nil)
	}
	trusted := map[string]bool{"S-1-5-18": true, "S-1-5-32-544": true}
	if ti, _, _, e := windows.LookupSID("", `NT SERVICE\TrustedInstaller`); e == nil {
		trusted[ti.String()] = true
	}
	if !trusted[owner.String()] {
		return fail(4, nil)
	}
	control, _, e := sd.Control()
	if e != nil {
		return fail(5, e)
	}
	if !ancestor && control&windows.SE_DACL_PROTECTED == 0 {
		return fail(5, nil)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return fail(6, e)
	}
	if acl == nil || acl.AceCount == 0 {
		return fail(6, nil)
	}
	const readOnly = windows.GENERIC_READ | windows.GENERIC_EXECUTE | windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.FILE_READ_ATTRIBUTES | windows.FILE_EXECUTE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return fail(7, e)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fail(7, nil)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if trusted[sid] {
			continue
		}
		allowed := uint32(readOnly)
		if ancestor {
			allowed |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
		}
		if uint32(ace.Mask)&^allowed != 0 {
			return fail(8, nil)
		}
		if !ancestor && sid != target {
			return fail(9, nil)
		}
	}
	return nil
}

// openMetadataAncestor requests only the existing parent metadata rights.
// FILE_OPEN never creates an entry; no synchronous/backup-intent options or
// generic access mapping may add rights. The caller still validates directory
// type, reparse/owner/DACL and keeps every ancestor handle pinned.
func openMetadataAncestor(path string) (windows.Handle, error) {
	name, e := metadataNTPath(path)
	if e != nil {
		return 0, e
	}
	objectName, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return 0, e
	}
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&h, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, &oa, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN, windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if e != nil {
		if h != 0 && h != windows.InvalidHandle {
			_ = windows.CloseHandle(h)
		}
		var native windows.NTStatus
		if errors.As(e, &native) {
			if code := native.Errno(); code != 0 {
				return 0, code // Preserve the bounded Win32 diagnostic contract.
			}
		}
		return 0, e
	}
	if h == 0 || h == windows.InvalidHandle {
		return 0, windows.ERROR_INVALID_HANDLE
	}
	return h, nil
}

func pinImmutable(path, target string, l *LockedConfiguration) (windows.Handle, error) {
	return pinImmutableDetail(path, target, l, 0)
}
func pinImmutableDetail(path, target string, l *LockedConfiguration, resource uint8) (windows.Handle, error) {
	fail := func(op, index uint8, e error) (windows.Handle, error) {
		return 0, configurationFailure(resource, op, index, e)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, `\\`) {
		return fail(13, 15, nil)
	}
	volume := filepath.VolumeName(path)
	if volume == "" {
		return fail(13, 15, nil)
	}
	current := volume + `\`
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), current), `\`)
	ancestors := []string{current}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fail(13, 15, nil)
		}
		current = filepath.Join(current, part)
		ancestors = append(ancestors, current)
	}
	for index, p := range ancestors {
		// All accepted fixed layouts have four ancestors. Overflow is rejected; no
		// arbitrary path information can be packed into the service-specific code.
		if index >= 15 {
			return fail(13, 15, nil)
		}
		h, e := openMetadataAncestor(p)
		if e != nil {
			return fail(1, uint8(index), e)
		}
		l.handles = append(l.handles, h)
		if e = immutableHandleDetail(h, target, true, true, resource, uint8(index)); e != nil {
			return 0, e
		}
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fail(1, 15, e)
	}
	l.handles = append(l.handles, h)
	if e = immutableHandleDetail(h, target, false, false, resource, 15); e != nil {
		return 0, e
	}
	return h, nil
}
func LoadConfiguration(path string) (*LockedConfiguration, error) {
	l := &LockedConfiguration{}
	good := false
	defer func() {
		if !good {
			_ = l.Close()
		}
	}()
	fail := func(op uint8, e error) (*LockedConfiguration, error) { return nil, configurationFailure(1, op, 15, e) }
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return fail(1, e)
	}
	l.handles = append(l.handles, h)
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return fail(2, e)
	}
	if info.FileSizeHigh != 0 || info.FileSizeLow > 8192 || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fail(2, nil)
	}
	b := make([]byte, 8193)
	var n uint32
	if e = windows.ReadFile(h, b, &n, nil); e != nil {
		return fail(10, e)
	}
	b = b[:n]
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&l.Configuration) != nil || d.Decode(new(any)) != io.EOF {
		return fail(11, nil)
	}
	if l.Configuration.Validate() != nil || l.Configuration.Plan.ConfigPath != path {
		return fail(12, nil)
	}
	if e = immutableHandleDetail(h, l.Configuration.Plan.TargetSID, false, false, 1, 15); e != nil {
		return nil, e
	}
	if _, e = pinImmutableDetail(path, l.Configuration.Plan.TargetSID, l, 2); e != nil {
		return nil, e
	}
	if _, e = pinImmutableDetail(l.Configuration.Plan.BinaryPath, l.Configuration.Plan.TargetSID, l, 3); e != nil {
		return nil, e
	}
	if l.Configuration.CAFile != "" {
		if _, e = pinImmutableDetail(l.Configuration.CAFile, l.Configuration.Plan.TargetSID, l, 4); e != nil {
			return nil, e
		}
	}
	good = true
	return l, nil
}

func (l *LockedConfiguration) ServiceSID() (string, error) {
	s, _, _, e := windows.LookupSID("", `NT SERVICE\`+l.Configuration.Plan.Name())
	if e != nil {
		return "", ErrIdentity
	}
	return s.String(), nil
}
