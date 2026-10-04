//go:build windows

package windowsaccount

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

func serviceManager(enumerate bool) (*mgr.Mgr, error) {
	access := uint32(windows.SC_MANAGER_CONNECT)
	if enumerate {
		access |= windows.SC_MANAGER_ENUMERATE_SERVICE
	}
	h, e := windows.OpenSCManager(nil, nil, access)
	if e != nil {
		return nil, ErrIdentity
	}
	return &mgr.Mgr{Handle: h}, nil
}
func serviceAbsent(p Plan) error {
	m, e := serviceManager(false)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := openService(m, p.Name(), windows.SERVICE_QUERY_STATUS)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if e == nil {
		s.Close()
	}
	return ErrPlan
}
func setServiceACL(p Plan) error {
	m, e := serviceManager(false)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	h, e := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(p.Name()), windows.WRITE_DAC|windows.READ_CONTROL)
	if e != nil {
		return ErrUncertain
	}
	defer windows.CloseServiceHandle(h)
	sd, e := windows.SecurityDescriptorFromString(`D:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)(A;;0x20005;;;` + p.TargetSID + `)`)
	if e != nil {
		return ErrPlan
	}
	fn := advapi.NewProc("SetServiceObjectSecurity")
	ok, _, _ := fn.Call(uintptr(h), uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
	if ok == 0 {
		return ErrUncertain
	}
	return nil
}
func openService(m *mgr.Mgr, name string, access uint32) (*mgr.Service, error) {
	h, e := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), access)
	if e != nil {
		return nil, e
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}
func exactService(m *mgr.Mgr, p Plan, extra ...uint32) (*mgr.Service, error) {
	mask := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS | windows.READ_CONTROL)
	for _, v := range extra {
		mask |= v
	}
	s, e := openService(m, p.Name(), mask)
	if e != nil {
		return nil, ErrUncertain
	}
	cfg, e := s.Config()
	if e != nil {
		s.Close()
		return nil, ErrUncertain
	}
	want := `"` + p.BinaryPath + `" daemon-user-service --config "` + p.ConfigPath + `"`
	if verifyConfiguredLocalPlanAccount(p, cfg.ServiceStartName) != nil || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || cfg.BinaryPathName != want {
		s.Close()
		return nil, ErrIdentity
	}
	if verifyServiceConfiguration(s.Handle, p.TargetSID) != nil {
		s.Close()
		return nil, ErrIdentity
	}
	return s, nil
}
func hashFile(path string) (string, error) {
	b, e := readRegular(path, 64<<20)
	if e != nil {
		return "", ErrPlan
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Install创建受保护材料与disabled服务，绝不隐式启动。每次权限/SCM修改前写pending。
// 任何失败保留receipt与精确阶段，不重置账号、重复安装或猜测回滚。
func Install(r InstallRequest, password []uint16) (_ Receipt, err error) {
	defer clear(password)
	if installerIdentity() != nil || r.Configuration.Validate() != nil {
		return Receipt{}, ErrPlan
	}
	p := r.Configuration.Plan
	if len(password) < 2 || len(password) > 257 || password[len(password)-1] != 0 {
		return Receipt{}, ErrPlan
	}
	if serviceAbsent(p) != nil {
		return Receipt{}, ErrPlan
	}
	for _, path := range []string{p.InstallDirectory(), filepath.Dir(p.StateDirectory())} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return Receipt{}, ErrPlan
		}
	}
	before, allow, deny, e := effectiveServiceRights(p)
	if e != nil {
		return Receipt{}, e
	}
	add, e := rightShouldBeAdded(before, allow, deny)
	if e != nil {
		return Receipt{}, e
	}
	if r.BinarySource == "" || r.BinarySHA256 == "" || ((r.Configuration.CAFile == "") != (r.CASource == "")) || ((r.CASource == "") != (r.CASHA256 == "")) {
		return Receipt{}, ErrPlan
	}
	if ensureAdminParent(`C:\Program Files\Harmonia`) != nil || ensureAdminParent(`C:\ProgramData\HarmoniaUser`) != nil {
		return Receipt{}, ErrPlan
	}
	if newOwnedDirectory(p.InstallDirectory(), p.TargetSID, false) != nil {
		return Receipt{}, ErrUncertain
	}
	j := &diskJournal{receipt: Receipt{Schema: "harmonia/windows-account-install/v1", Configuration: r.Configuration, Stage: "directory-created", DirectRightsBefore: before, Files: map[string]string{}}, path: p.InstallDirectory() + `\install.json`}
	defer func() {
		if err != nil {
			err = ErrUncertain
		}
	}()
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	j.receipt.Pending = "create-state-directory"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if e = newOwnedDirectory(filepath.Dir(p.StateDirectory()), p.TargetSID, false); e != nil {
		return j.receipt, e
	}
	if e = newOwnedDirectory(p.StateDirectory(), p.TargetSID, true); e != nil {
		return j.receipt, e
	}
	j.receipt.Pending = "copy-protected-files"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if e = copyOwned(r.BinarySource, p.BinaryPath, r.BinarySHA256, p.TargetSID); e != nil {
		return j.receipt, e
	}
	j.receipt.Files[p.BinaryPath] = strings.ToLower(r.BinarySHA256)
	if r.CASource != "" {
		if e = copyOwned(r.CASource, r.Configuration.CAFile, r.CASHA256, p.TargetSID); e != nil {
			return j.receipt, e
		}
		j.receipt.Files[r.Configuration.CAFile] = strings.ToLower(r.CASHA256)
	}
	if e = createOwnedJSON(p.ConfigPath, r.Configuration, p.TargetSID); e != nil {
		return j.receipt, e
	}
	j.receipt.Files[p.ConfigPath], e = hashFile(p.ConfigPath)
	if e != nil {
		return j.receipt, e
	}
	j.receipt.Pending = ""
	j.receipt.Stage = "files-ready"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if add {
		j.receipt.Pending = "grant-service-logon"
		if e = j.save(); e != nil {
			return j.receipt, e
		}
		if e = changeServiceRight(p.TargetSID, false); e != nil {
			return j.receipt, e
		}
		after, e := directRights(p.TargetSID)
		if e != nil || !rightAdditionMatches(before, after) {
			return j.receipt, ErrUncertain
		}
		j.receipt.AddedServiceRight = true
		j.receipt.Pending = ""
		j.receipt.Stage = "right-granted"
		if e = j.save(); e != nil {
			return j.receipt, e
		}
	}
	result := CreateDisabled(p, password, j)
	if !result.Created || !result.Configured {
		return j.receipt, ErrUncertain
	}
	j.receipt.Pending = "service-dacl"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if e = setServiceACL(p); e != nil {
		return j.receipt, e
	}
	lock, e := LoadConfiguration(p.ConfigPath)
	if e != nil {
		return j.receipt, e
	}
	if e = lock.Close(); e != nil {
		return j.receipt, e
	}
	m, e := serviceManager(false)
	if e != nil {
		return j.receipt, e
	}
	defer m.Disconnect()
	s, e := exactService(m, p)
	if e != nil {
		return j.receipt, e
	}
	cfg, e := s.Config()
	s.Close()
	if e != nil || cfg.StartType != windows.SERVICE_DISABLED {
		return j.receipt, ErrUncertain
	}
	j.receipt.Pending = ""
	j.receipt.Stage = "installed-disabled"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	return j.receipt, nil
}

func waitState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		v, e := s.Query()
		if e != nil {
			return ErrUncertain
		}
		if v.State == want {
			if want == svc.Stopped && (v.Win32ExitCode != 0 || v.ServiceSpecificExitCode != 0) {
				return ErrUncertain
			}
			return nil
		}
		if want == svc.Running && v.State == svc.Stopped {
			return ErrUncertain
		}
		time.Sleep(100 * time.Millisecond)
	}
	return ErrUncertain
}

func StartInstalled(config string) (Receipt, error) {
	j, lock, e := loadJournal(config)
	if e != nil {
		return Receipt{}, e
	}
	defer lock.Close()
	p := j.receipt.Configuration.Plan
	m, e := serviceManager(false)
	if e != nil {
		return j.receipt, e
	}
	defer m.Disconnect()
	s, e := exactService(m, p, windows.SERVICE_START|windows.SERVICE_CHANGE_CONFIG)
	if e != nil {
		return j.receipt, e
	}
	defer s.Close()
	cfg, cfgErr := s.Config()
	status, statusErr := s.Query()
	if cfgErr != nil || statusErr != nil {
		return j.receipt, ErrUncertain
	}
	resume, allowed := mayStartReceipt(j.receipt, uint32(status.State), cfg.StartType)
	if !allowed {
		return j.receipt, ErrUncertain
	}
	// Save the result of each exact operation before a later operation can hide
	// it. Query failure is represented explicitly rather than pretending zero
	// status/exit codes were observed. No raw error text is stored.
	record := func(stage string, operationErr error) error {
		result := startResult(stage, operationErr)
		currentConfig, configErr := s.Config()
		currentStatus, queryErr := s.Query()
		if configErr == nil && queryErr == nil {
			result.StatusRead = true
			result.State = uint32(currentStatus.State)
			result.StartType = currentConfig.StartType
			result.Win32ExitCode = currentStatus.Win32ExitCode
			result.ServiceSpecificExitCode = currentStatus.ServiceSpecificExitCode
		}
		j.receipt.LastStart = &result
		return j.save()
	}
	j.receipt.Pending = "start-service"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	if resume {
		if record("resume-manual", nil) != nil {
			return j.receipt, ErrUncertain
		}
	} else {
		e = windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_DEMAND_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil)
		if saveErr := record("change-demand", e); e != nil || saveErr != nil {
			return j.receipt, ErrUncertain
		}
	}
	e = s.Start()
	if saveErr := record("start-service", e); e != nil || saveErr != nil {
		return j.receipt, ErrUncertain
	}
	e = waitState(s, svc.Running)
	if saveErr := record("wait-running", e); e != nil || saveErr != nil {
		return j.receipt, ErrUncertain
	}
	// 真实Running后才启用无人登录自动启动。
	j.receipt.Pending = "enable-automatic"
	if e = j.save(); e != nil {
		return j.receipt, e
	}
	e = windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil)
	if saveErr := record("enable-automatic", e); e != nil || saveErr != nil {
		return j.receipt, ErrUncertain
	}
	j.receipt.Pending = ""
	j.receipt.Stage = "running-automatic"
	return j.receipt, j.save()
}
