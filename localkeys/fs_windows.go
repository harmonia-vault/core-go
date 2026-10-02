//go:build windows

package localkeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsFS struct {
	directory string
	owner     string
	root      windows.Handle
	lock      *os.File
	overlap   windows.Overlapped
	sd        *windows.SECURITY_DESCRIPTOR
}

func CurrentUserID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}
func validWindowsSID(value, prefix string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid.String() == value && strings.HasPrefix(value, prefix)
}
func privateWindowsSD(owner string, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	return windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;" + inherit + ";FA;;;" + owner + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)")
}
func sdAttributes(sd *windows.SECURITY_DESCRIPTOR) *windows.SecurityAttributes {
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
}
func openSecureFS(c Config) (secureFS, string, error) {
	owner, err := CurrentUserID()
	if err != nil {
		return nil, "", err
	}
	if !validWindowsSID(c.UserID, "S-1-5-21-") {
		return nil, "", ErrIdentity
	}
	if c.ServiceSID == "" {
		if owner != c.UserID {
			return nil, "", ErrIdentity
		}
	} else if !validWindowsSID(c.ServiceSID, "S-1-5-80-") || owner != c.ServiceSID {
		return nil, "", ErrIdentity
	} else {
		sum := sha256.Sum256([]byte(c.UserID))
		expected, _, _, err := windows.LookupSID("", `NT SERVICE\Harmonia-`+hex.EncodeToString(sum[:6]))
		if err != nil || expected.String() != c.ServiceSID {
			return nil, "", ErrIdentity
		}
	}
	if !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory || strings.HasPrefix(c.Directory, `\\`) || filepath.VolumeName(c.Directory) == "" {
		return nil, "", ErrPermission
	}
	volume := filepath.VolumeName(c.Directory)
	current := volume + string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(c.Directory, current), string(os.PathSeparator))
	dirSD, err := privateWindowsSD(owner, true)
	if err != nil {
		return nil, "", err
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, "", ErrPermission
		}
		current = filepath.Join(current, part)
		attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err == windows.ERROR_FILE_NOT_FOUND && index == len(parts)-1 {
			err = windows.CreateDirectory(windows.StringToUTF16Ptr(current), sdAttributes(dirSD))
			if err == nil {
				attrs, err = windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
			}
		}
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, "", ErrPermission
		}
	}
	root, err := windows.CreateFile(windows.StringToUTF16Ptr(c.Directory), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, "", ErrPermission
	}
	fileSD, err := privateWindowsSD(owner, false)
	if err != nil {
		windows.CloseHandle(root)
		return nil, "", err
	}
	fs := &windowsFS{directory: c.Directory, owner: owner, root: root, sd: fileSD}
	if err := fs.validate(root, true); err != nil {
		windows.CloseHandle(root)
		return nil, "", err
	}
	lock, err := fs.create("vault.lock", windows.OPEN_ALWAYS)
	if err != nil {
		windows.CloseHandle(root)
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, "", ErrBusy
		}
		return nil, "", err
	}
	fs.lock = lock
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &fs.overlap); err != nil {
		lock.Close()
		windows.CloseHandle(root)
		return nil, "", ErrBusy
	}
	return fs, owner, nil
}
func (f *windowsFS) validate(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrPermission
	}
	if directory {
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return ErrPermission
		}
	} else if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
		return ErrPermission
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrPermission
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return ErrPermission
	}
	allowed := map[string]bool{f.owner: true, "S-1-5-18": true, "S-1-5-32-544": true}
	if !allowed[owner.String()] {
		return ErrPermission
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrPermission
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrPermission
	}
	currentAllowed := false
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrPermission
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		identity := sid.String()
		if !allowed[identity] {
			return ErrPermission
		}
		if identity == f.owner {
			currentAllowed = true
		}
	}
	if !currentAllowed {
		return ErrPermission
	}
	return nil
}
func (f *windowsFS) guard() error {
	if err := f.validate(f.root, true); err != nil {
		return err
	}
	if f.lock != nil {
		return f.validate(windows.Handle(f.lock.Fd()), false)
	}
	return nil
}
func (f *windowsFS) create(name string, creation uint32) (*os.File, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(f.directory, name)), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ, sdAttributes(f.sd), creation, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err := f.validate(handle, false); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}
func (f *windowsFS) open(name string) (*os.File, error) {
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(filepath.Join(f.directory, name)), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == windows.ERROR_FILE_NOT_FOUND {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrPermission
	}
	if err := f.validate(handle, false); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}
func (f *windowsFS) Read(name string, max int) ([]byte, error) {
	if err := f.guard(); err != nil {
		return nil, err
	}
	file, err := f.open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(max) {
		return nil, ErrCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, ErrCorrupt
	}
	return data, nil
}
func (f *windowsFS) Write(name string, data []byte, exclusive bool) error {
	if err := f.guard(); err != nil {
		return err
	}
	if existing, err := f.open(name); err == nil {
		existing.Close()
		if exclusive {
			return os.ErrExist
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return err
	}
	tmp := ".localkeys-" + hex.EncodeToString(random[:])
	file, err := f.create(tmp, windows.CREATE_NEW)
	if err != nil {
		return err
	}
	path := filepath.Join(f.directory, tmp)
	defer os.Remove(path)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if !exclusive {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(path), windows.StringToUTF16Ptr(filepath.Join(f.directory, name)), flags)
}
func (f *windowsFS) Delete(name string) error {
	if err := f.guard(); err != nil {
		return err
	}
	file, err := f.open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	file.Close()
	return os.Remove(filepath.Join(f.directory, name))
}
func (f *windowsFS) Close() error {
	if f.lock == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(f.lock.Fd()), 0, 1, 0, &f.overlap)
	err = errors.Join(err, f.lock.Close(), windows.CloseHandle(f.root))
	f.lock = nil
	return err
}
func protectorName() string { return "windows-dpapi-machine-v1" }
func blob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}
func dpapiResult(output windows.DataBlob) ([]byte, error) {
	if output.Data != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	}
	if output.Data == nil || output.Size == 0 || output.Size > 65536 {
		return nil, ErrCorrupt
	}
	view := unsafe.Slice(output.Data, int(output.Size))
	data := append([]byte(nil), view...)
	clear(view)
	return data, nil
}
func protectMachineKey(key []byte, c Config, owner string) ([]byte, error) {
	var output windows.DataBlob
	entropy := []byte(keySchema + "\x00" + c.UserID + "\x00" + owner)
	if err := windows.CryptProtectData(blob(key), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &output); err != nil {
		return nil, err
	}
	return dpapiResult(output)
}
func unprotectMachineKey(data []byte, c Config, owner string) ([]byte, error) {
	var output windows.DataBlob
	entropy := []byte(keySchema + "\x00" + c.UserID + "\x00" + owner)
	if err := windows.CryptUnprotectData(blob(data), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	return dpapiResult(output)
}
