//go:build windows

package windowsaccount

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

type operationLock struct {
	config *LockedConfiguration
	file   *os.File
	path   string
}

func (l *operationLock) Close() error {
	var e error
	if l.config != nil {
		e = errors.Join(e, l.config.Close())
		l.config = nil
	}
	if l.file != nil {
		e = errors.Join(e, l.file.Close())
		l.file = nil
	}
	return e
}
func loadJournal(config string) (_ *diskJournal, _ *operationLock, err error) {
	if installerIdentity() != nil {
		return nil, nil, ErrIdentity
	}
	cfg, e := LoadConfiguration(config)
	if e != nil {
		return nil, nil, e
	}
	l := &operationLock{config: cfg, path: cfg.Configuration.Plan.InstallDirectory() + `\installer.lock`}
	good := false
	defer func() {
		if !good {
			_ = l.Close()
		}
	}()
	// 内核共享模式负责排他；进程崩溃释放handle，残留空锁文件不会永久卡死。
	// 新文件在CreateFile时便带管理员DACL；既有文件必须同样受保护。
	sd, e := windows.SecurityDescriptorFromString(adminFile)
	if e != nil {
		return nil, nil, ErrPlan
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	lockHandle, e := windows.CreateFile(windows.StringToUTF16Ptr(l.path), windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, nil, ErrUncertain
	}
	l.file = os.NewFile(uintptr(lockHandle), "installer-lock")
	if immutableHandle(lockHandle, "", false, false) != nil {
		return nil, nil, ErrPlan
	}
	path := cfg.Configuration.Plan.InstallDirectory() + `\install.json`
	pins := &LockedConfiguration{}
	h, e := pinImmutable(path, "", pins)
	if e != nil {
		pins.Close()
		return nil, nil, e
	}
	data := make([]byte, 32769)
	var count uint32
	e = windows.ReadFile(h, data, &count, nil)
	closeErr := pins.Close()
	if e != nil || closeErr != nil || count > 32768 {
		return nil, nil, ErrPlan
	}
	var receipt Receipt
	d := json.NewDecoder(bytes.NewReader(data[:count]))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF || receipt.Schema != "harmonia/windows-account-install/v1" || receipt.Configuration != cfg.Configuration || len(receipt.Files) < 2 || len(receipt.Files) > 3 {
		return nil, nil, ErrPlan
	}
	expected := map[string]bool{cfg.Configuration.Plan.BinaryPath: true, config: true}
	if cfg.Configuration.CAFile != "" {
		expected[cfg.Configuration.CAFile] = true
	}
	if len(expected) != len(receipt.Files) {
		return nil, nil, ErrPlan
	}
	for path, want := range receipt.Files {
		if !expected[path] {
			return nil, nil, ErrPlan
		}
		got, e := hashFile(path)
		if e != nil || got != want {
			return nil, nil, ErrPlan
		}
	}
	good = true
	return &diskJournal{receipt: receipt, path: path}, l, nil
}

func StopInstalled(config string) (Receipt, error) {
	j, l, e := loadJournal(config)
	if e != nil {
		return Receipt{}, e
	}
	defer l.Close()
	if !mayStopReceipt(j.receipt) {
		return j.receipt, ErrUncertain
	}
	m, e := serviceManager(false)
	if e != nil {
		return j.receipt, e
	}
	defer m.Disconnect()
	s, e := exactService(m, j.receipt.Configuration.Plan, windows.SERVICE_STOP|windows.SERVICE_CHANGE_CONFIG)
	if e != nil {
		return j.receipt, e
	}
	defer s.Close()
	j.receipt.Pending = "disable-and-drain"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_DISABLED, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil) != nil {
		return j.receipt, ErrUncertain
	}
	v, e := s.Query()
	if e != nil {
		return j.receipt, ErrUncertain
	}
	if v.State != svc.Stopped {
		if _, e = s.Control(svc.Stop); e != nil {
			return j.receipt, ErrUncertain
		}
		if e = waitState(s, svc.Stopped); e != nil {
			return j.receipt, e
		}
	}
	j.receipt.Pending = ""
	j.receipt.Stage = "stopped-disabled"
	return j.receipt, j.save()
}

// RestorationMarker是普通用户完成真实本机恢复后的本地交接记录，绑定两份密文状态摘要。
// 它不提供云信任或跨用户授权；任一后续状态变化都会使其失效。
type RestorationMarker struct {
	Schema          string `json:"schema"`
	TargetSID       string `json:"targetSID"`
	ServiceName     string `json:"serviceName"`
	StateSHA256     string `json:"stateSha256"`
	OriginalsSHA256 string `json:"originalsSha256"`
}

func WriteRestorationMarker(p Plan) error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != p.TargetSID || p.Validate() != nil {
		return ErrIdentity
	}
	state, e := hashFile(filepath.Join(p.StateDirectory(), "state.v1.enc"))
	if e != nil {
		return e
	}
	originals, e := hashFile(filepath.Join(p.StateDirectory(), "windows-originals.v1.enc"))
	if e != nil {
		return e
	}
	marker := RestorationMarker{"harmonia/windows-restored/v1", p.TargetSID, p.Name(), state, originals}
	path := filepath.Join(p.StateDirectory(), "restoration.json")
	// 已有marker须先验证属于本实例；正常重试同状态不创建第二份交接记录。
	if data, e := readRegular(path, 4096); e == nil {
		var old RestorationMarker
		if json.Unmarshal(data, &old) != nil || old != marker {
			return ErrUncertain
		}
		return nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrUncertain
	}
	b, _ := json.Marshal(marker)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrUncertain
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func StoppedAndDisabled(p Plan) error {
	m, e := serviceManager(false)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := exactService(m, p)
	if e != nil {
		return e
	}
	defer s.Close()
	c, e := s.Config()
	if e != nil || c.StartType != windows.SERVICE_DISABLED {
		return ErrUncertain
	}
	v, e := s.Query()
	if e != nil || v.State != svc.Stopped {
		return ErrUncertain
	}
	return nil
}
func validateRestoration(p Plan) error {
	data, e := readRegular(filepath.Join(p.StateDirectory(), "restoration.json"), 4096)
	if e != nil || len(data) > 4096 {
		return ErrUncertain
	}
	var marker RestorationMarker
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&marker) != nil || d.Decode(new(any)) != io.EOF || marker.Schema != "harmonia/windows-restored/v1" || marker.TargetSID != p.TargetSID || marker.ServiceName != p.Name() {
		return ErrUncertain
	}
	for name, want := range map[string]string{"state.v1.enc": marker.StateSHA256, "windows-originals.v1.enc": marker.OriginalsSHA256} {
		got, e := hashFile(filepath.Join(p.StateDirectory(), name))
		if e != nil || got != want {
			return ErrUncertain
		}
	}
	for _, name := range []string{"session.v1.enc", "device.v1.enc", "trust.v1.enc", "writes.v1.enc", "recovery.dag.v1.enc"} {
		if _, e = os.Lstat(filepath.Join(p.StateDirectory(), name)); !errors.Is(e, os.ErrNotExist) {
			return ErrUncertain
		}
	}
	return nil
}

// RemoveInstalled仅在同用户CLI的逐键恢复已完成、服务停止禁用后移除本实例。
// 账号级权限若被其它服务采用则保留并在receipt中标明，不撤销其它主体所需权限。
func RemoveInstalled(config string) (Receipt, error) {
	j, l, e := loadJournal(config)
	if e != nil {
		return Receipt{}, e
	}
	defer l.Close()
	p := j.receipt.Configuration.Plan
	if j.receipt.Pending != "" || j.receipt.Stage != "stopped-disabled" || StoppedAndDisabled(p) != nil || validateRestoration(p) != nil {
		return j.receipt, ErrUncertain
	}
	entries, e := os.ReadDir(p.StateDirectory())
	if e != nil {
		return j.receipt, ErrUncertain
	}
	allowed := map[string]bool{"machine-key.v1": true, "vault.lock": true, "state.v1.enc": true, "windows-originals.v1.enc": true, "restoration.json": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.IsDir() {
			return j.receipt, ErrUncertain
		}
		a, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(filepath.Join(p.StateDirectory(), entry.Name())))
		if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return j.receipt, ErrUncertain
		}
	}
	j.receipt.Pending = "delete-service"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	m, e := serviceManager(false)
	if e != nil {
		return j.receipt, e
	}
	s, e := exactService(m, p, windows.DELETE)
	if e != nil {
		m.Disconnect()
		return j.receipt, e
	}
	e = s.Delete()
	s.Close()
	m.Disconnect()
	if e != nil {
		return j.receipt, ErrUncertain
	}
	deadline := time.Now().Add(10 * time.Second)
	for serviceAbsent(p) != nil {
		if time.Now().After(deadline) {
			return j.receipt, ErrUncertain
		}
		time.Sleep(100 * time.Millisecond)
	}
	j.receipt.ServiceCreated = false
	j.receipt.Pending = ""
	j.receipt.Stage = "service-removed"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if j.receipt.AddedServiceRight {
		others, e := otherServicesForSID(p)
		if e != nil {
			// 读取/身份/观察不完整绝不能转成零使用者并撤权。
			j.receipt.Stage = "service-removed-right-check-incomplete"
			j.receipt.Pending = "verify-other-service-users"
			return j.receipt, errors.Join(ErrUncertain, j.save())
		}
		before, e := directRights(p.TargetSID)
		if e != nil {
			return j.receipt, e
		}
		r := RightReceipt{TargetSID: p.TargetSID, DirectBefore: hasRight(j.receipt.DirectRightsBefore, ServiceLogonRight), AddedByInstall: true}
		if r.MayRemove(p.TargetSID, hasRight(before, ServiceLogonRight), others, true) {
			j.receipt.Pending = "remove-added-service-logon"
			if e = j.save(); e != nil {
				return j.receipt, e
			}
			if e = changeServiceRight(p.TargetSID, true); e != nil {
				return j.receipt, e
			}
			after, e := directRights(p.TargetSID)
			if e != nil || !rightRemovalMatches(before, after) {
				return j.receipt, ErrUncertain
			}
			j.receipt.AddedServiceRight = false
			j.receipt.Pending = ""
		} else if others > 0 {
			j.receipt.Stage = "service-removed-right-retained"
			_ = j.save()
			return j.receipt, ErrUncertain
		}
	}
	j.receipt.Stage = "remove-owned-files"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	// 先关闭映像/config pins和本次操作锁；仅删除精确白名单叶文件与空目录。
	if e = l.Close(); e != nil {
		return j.receipt, e
	}
	for _, entry := range entries {
		if e = os.Remove(filepath.Join(p.StateDirectory(), entry.Name())); e != nil {
			return j.receipt, ErrUncertain
		}
	}
	if os.Remove(p.StateDirectory()) != nil || os.Remove(filepath.Dir(p.StateDirectory())) != nil {
		return j.receipt, ErrUncertain
	}
	for path := range j.receipt.Files {
		if os.Remove(path) != nil {
			return j.receipt, ErrUncertain
		}
	}
	if os.Remove(l.path) != nil || os.Remove(j.path) != nil || os.Remove(p.InstallDirectory()) != nil {
		return j.receipt, ErrUncertain
	}
	j.receipt.Stage = "uninstalled"
	return j.receipt, nil
}
