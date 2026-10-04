//go:build windows

package windowsaccount

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const adminFile = `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`
const adminDirectory = `O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`

func readRegular(path string, maximum int64) ([]byte, error) {
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e == windows.ERROR_FILE_NOT_FOUND {
		return nil, os.ErrNotExist
	}
	if e != nil {
		return nil, ErrPlan
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > uint64(maximum) {
		windows.CloseHandle(h)
		return nil, ErrPlan
	}
	f := os.NewFile(uintptr(h), "owned-record")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(b)) > maximum {
		return nil, ErrPlan
	}
	return b, nil
}
func installerIdentity() error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != "S-1-5-18" {
		return ErrIdentity
	}
	return nil
}
func protectNew(path, descriptor string) error {
	sd, e := windows.SecurityDescriptorFromString(descriptor)
	if e != nil {
		return ErrPlan
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return ErrPlan
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return ErrPlan
	}
	if windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil) != nil {
		return ErrUncertain
	}
	return nil
}
func ensureAdminParent(path string) error {
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		if e = os.Mkdir(path, 0700); e != nil {
			return ErrUncertain
		}
		return protectNew(path, sharedParentDirectory)
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return ErrPlan
	}
	defer windows.CloseHandle(h)
	// Legacy admin-only or foreign ACLs are not silently changed here. Updating
	// an existing installation requires a separately reviewed upgrade operation.
	return verifySharedParent(h)
}
func newOwnedDirectory(path, sid string, writable bool) error {
	if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
		return ErrPlan
	}
	if e := os.Mkdir(path, 0700); e != nil {
		return ErrUncertain
	}
	return protectNew(path, ownedDirectoryDescriptor(sid, writable))
}
func ownedDirectoryDescriptor(sid string, writable bool) string {
	rights := "0x1200a9"
	if writable {
		rights = "FA"
	}
	return adminDirectory + `(A;OICI;` + rights + `;;;` + sid + `)`
}
func copyOwned(source, destination, want, sid string) error {
	if len(want) != 64 {
		return ErrPlan
	}
	if _, e := hex.DecodeString(want); e != nil {
		return ErrPlan
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(source), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return ErrPlan
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > 64<<20 {
		windows.CloseHandle(h)
		return ErrPlan
	}
	in := os.NewFile(uintptr(h), "reviewed-source")
	defer in.Close()
	out, e := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrUncertain
	}
	hash := sha256.New()
	_, e = io.Copy(io.MultiWriter(out, hash), io.LimitReader(in, 64<<20))
	if e == nil {
		e = out.Sync()
	}
	e = errors.Join(e, out.Close())
	if e != nil || hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(want) {
		return ErrUncertain
	}
	return protectNew(destination, adminFile+`(A;;0x1200a9;;;`+sid+`)`)
}
func createOwnedJSON(path string, value any, sid string) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return ErrPlan
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrUncertain
	}
	_, e = f.Write(append(b, '\n'))
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return ErrUncertain
	}
	acl := adminFile
	if sid != "" {
		acl += `(A;;0x1200a9;;;` + sid + `)`
	}
	return protectNew(path, acl)
}

type diskJournal struct {
	receipt Receipt
	path    string
}

func (j *diskJournal) save() error {
	b, e := json.MarshalIndent(j.receipt, "", "  ")
	if e != nil {
		return ErrPlan
	}
	file, e := os.CreateTemp(filepath.Dir(j.path), ".receipt-")
	if e != nil {
		return ErrUncertain
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if e = protectNew(tmp, adminFile); e != nil {
		file.Close()
		return e
	}
	_, e = file.Write(append(b, '\n'))
	if e == nil {
		e = file.Sync()
	}
	e = errors.Join(e, file.Close())
	if e != nil {
		return ErrUncertain
	}
	if windows.MoveFileEx(windows.StringToUTF16Ptr(tmp), windows.StringToUTF16Ptr(j.path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return ErrUncertain
	}
	return nil
}
func (j *diskJournal) BeforeCreate(p Plan) error {
	if p != j.receipt.Configuration.Plan {
		return ErrPlan
	}
	j.receipt.Pending = "create-disabled-service"
	return j.save()
}
func (j *diskJournal) AfterCreate(p Plan, r CreateResult) error {
	if p != j.receipt.Configuration.Plan {
		return ErrPlan
	}
	j.receipt.LastCreate = &r
	j.receipt.ServiceCreated = r.Created
	j.receipt.Stage = r.Stage
	if r.Configured {
		j.receipt.Pending = ""
	}
	return j.save()
}
