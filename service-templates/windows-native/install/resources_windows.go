//go:build windows

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const adminFile = `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`
const adminDirectory = `O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`

func protect(path, sddl string) error {
	sd, e := windows.SecurityDescriptorFromString(sddl)
	if e != nil {
		return rejected
	}
	owner, _, e := sd.Owner()
	if e != nil {
		return rejected
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return rejected
	}
	if windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil) != nil {
		return rejected
	}
	return nil
}
func copyBinary(src, dst, want string) error {
	got, e := hash(src)
	if e != nil || got != want {
		return rejected
	}
	in, e := os.Open(src)
	if e != nil {
		return rejected
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return rejected
	}
	_, e = io.Copy(out, in)
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e != nil || ce != nil {
		return rejected
	}
	return protect(dst, adminFile)
}
func requiredPrivileges(s *mgr.Service, names []string) error {
	units := []uint16{}
	for _, name := range names {
		value, _ := windows.UTF16FromString(name)
		units = append(units, value...)
	}
	units = append(units, 0)
	info := struct{ Names *uint16 }{&units[0]}
	if windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info))) != nil {
		return rejected
	}
	return nil
}
func provision(m *manifest, stage string) error {
	if _, e := os.Lstat(m.Install); !os.IsNotExist(e) {
		return rejected
	}
	if _, e := accountSID(m.AccountName); e == nil {
		return rejected
	}
	for _, entry := range []struct{ name, want string }{{"harmonia-profile-arm64.exe", m.ProfileSHA256}, {"harmonia-native-sync-arm64.exe", m.SyncSHA256}} {
		got, e := hash(filepath.Join(stage, entry.name))
		if e != nil || got != entry.want {
			return rejected
		}
	}
	if os.Mkdir(m.Install, 0700) != nil || protect(m.Install, adminDirectory) != nil {
		return rejected
	}
	m.Phase = "directory"
	if m.save() != nil {
		return rejected
	}
	pw, e := randomPassword()
	if e != nil {
		return e
	}
	defer clear(pw)
	if m.begin("account-create") != nil {
		return rejected
	}
	if addAccount(m.AccountName, pw) != nil {
		return rejected
	}
	m.AccountCreated = true
	m.Phase = "account"
	m.TargetSID, e = accountSID(m.AccountName)
	if e != nil || m.committed() != nil {
		return rejected
	}
	if joinUsers(m.TargetSID) != nil {
		return rejected
	}
	if m.begin("profile-create") != nil {
		return rejected
	}
	if freshProfile(m.TargetSID, m.AccountName, m) != nil {
		return rejected
	}
	m.ProfileCreated = true
	if m.committed() != nil {
		return rejected
	}
	if m.begin("batch-add") != nil {
		return rejected
	}
	if batchRight(m.TargetSID, false, m) != nil {
		return rejected
	}
	m.BatchGranted = true
	m.Phase = "batch"
	if m.committed() != nil {
		return rejected
	}
	c := m.config()
	if copyBinary(filepath.Join(stage, "harmonia-profile-arm64.exe"), c.Executable, m.ProfileSHA256) != nil || copyBinary(filepath.Join(stage, "harmonia-native-sync-arm64.exe"), c.SyncExecutable, m.SyncSHA256) != nil {
		return rejected
	}
	manager, e := mgr.Connect()
	if e != nil {
		return rejected
	}
	defer manager.Disconnect()
	for _, entry := range []struct {
		name, exe, account string
		args, privileges   []string
	}{{c.BrokerServiceName(), c.Executable, "LocalSystem", []string{"broker", "--config", c.ConfigurationFile}, []string{"SeChangeNotifyPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeImpersonatePrivilege"}}, {c.SyncServiceName(), c.SyncExecutable, `NT SERVICE\` + c.SyncServiceName(), []string{"--config", c.ConfigurationFile}, []string{"SeChangeNotifyPrivilege"}}} {
		if m.begin("service-create") != nil {
			return rejected
		}
		service, e := manager.CreateService(entry.name, entry.exe, mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: windows.SERVICE_DEMAND_START, ErrorControl: windows.SERVICE_ERROR_NORMAL, ServiceStartName: entry.account, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, entry.args...)
		if e != nil {
			return rejected
		}
		m.Services = append(m.Services, entry.name)
		m.Phase = "services"
		if m.committed() != nil {
			service.Close()
			return rejected
		}
		e = requiredPrivileges(service, entry.privileges)
		service.Close()
		if e != nil {
			return e
		}
	}
	syncSID, _, _, e := windows.LookupSID("", `NT SERVICE\`+c.SyncServiceName())
	if e != nil {
		return rejected
	}
	m.SyncSID = syncSID.String()
	brokerSID, _, _, e := windows.LookupSID("", `NT SERVICE\`+c.BrokerServiceName())
	if e != nil {
		return rejected
	}
	m.BrokerSID = brokerSID.String()
	c = m.config()
	if c.Validate() != nil {
		return rejected
	}
	data, _ := json.Marshal(c)
	if os.WriteFile(c.ConfigurationFile, data, 0600) != nil {
		return rejected
	}
	readers := `(A;;GRGX;;;` + m.TargetSID + `)(A;;GRGX;;;` + m.SyncSID + `)`
	for _, path := range []string{c.ConfigurationFile, c.Executable, c.SyncExecutable} {
		if protect(path, adminFile+readers) != nil {
			return rejected
		}
	}
	if protect(m.Install, adminFile+readers) != nil {
		return rejected
	}
	vault := filepath.Join(m.Install, "vault")
	if os.Mkdir(vault, 0700) != nil || protect(vault, adminDirectory+`(A;OICI;FA;;;`+m.SyncSID+`)`) != nil {
		return rejected
	}
	if m.save() != nil {
		return rejected
	}
	if createTaskFolder(m) != nil {
		return rejected
	}
	if m.begin("task-self-register") != nil {
		return rejected
	}
	if selfRegister(m, pw) != nil {
		return rejected
	}
	m.TaskRegistered = true
	if m.committed() != nil {
		return rejected
	}
	if lockTask(m) != nil {
		return rejected
	}
	m.Phase = "ready-for-reviewed-start"
	return m.save()
}
func waitService(s *mgr.Service, want svc.State, duration time.Duration) error {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		status, e := s.Query()
		if e != nil {
			return rejected
		}
		if status.State == want {
			return nil
		}
		if want == svc.Running && status.State == svc.Stopped {
			return rejected
		}
		time.Sleep(100 * time.Millisecond)
	}
	return rejected
}
func start(m *manifest) error {
	if m.Phase != "ready-for-reviewed-start" {
		return rejected
	}
	c := m.config()
	for _, entry := range []struct{ path, want string }{{c.Executable, m.ProfileSHA256}, {c.SyncExecutable, m.SyncSHA256}} {
		got, e := hash(entry.path)
		if e != nil || got != entry.want {
			return rejected
		}
	}
	result := filepath.Join(m.Install, "vault", "result.json")
	if _, e := os.Lstat(result); !os.IsNotExist(e) {
		return rejected
	}
	manager, e := mgr.Connect()
	if e != nil {
		return rejected
	}
	defer manager.Disconnect()
	broker, e := manager.OpenService(c.BrokerServiceName())
	if e != nil {
		return rejected
	}
	defer broker.Close()
	m.Phase = "broker-start"
	if m.save() != nil {
		return rejected
	}
	if broker.Start() != nil || waitService(broker, svc.Running, 30*time.Second) != nil {
		return rejected
	}
	sync, e := manager.OpenService(c.SyncServiceName())
	if e != nil {
		return rejected
	}
	defer sync.Close()
	m.Phase = "sync-start"
	if m.save() != nil {
		return rejected
	}
	if sync.Start() != nil {
		return rejected
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if _, e = os.Stat(result); e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, e := os.ReadFile(result)
	if e != nil || len(b) > 4096 {
		return rejected
	}
	var report struct {
		Scope string `json:"scope"`
		Stage string `json:"stage"`
		Pass  bool   `json:"pass"`
	}
	if json.Unmarshal(b, &report) != nil || report.Scope != "native-provider-only" || !report.Pass || report.Stage != "complete" {
		m.Phase = "probe-" + report.Stage
		_ = m.save()
		return rejected
	}
	if waitService(sync, svc.Stopped, 10*time.Second) != nil {
		return rejected
	}
	status, e := sync.Query()
	if e != nil || status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
		return rejected
	}
	if taskCompleted(m) != nil {
		return rejected
	}
	hive, e := registry.OpenKey(registry.USERS, m.TargetSID, registry.QUERY_VALUE)
	if e != nil {
		return rejected
	}
	_ = hive.Close()
	m.Phase = "broker-stop"
	if m.save() != nil {
		return rejected
	}
	if _, e = broker.Control(svc.Stop); e != nil || waitService(broker, svc.Stopped, 35*time.Second) != nil {
		return rejected
	}
	status, e = broker.Query()
	if e != nil || status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
		return rejected
	}
	m.Phase = "native-provider-complete"
	return m.save()
}
func cleanup(m *manifest) error {
	c := m.config()
	manager, e := mgr.Connect()
	if e != nil {
		return rejected
	}
	defer manager.Disconnect()
	for _, name := range []string{c.SyncServiceName(), c.BrokerServiceName()} {
		owned := false
		for _, n := range m.Services {
			owned = owned || n == name
		}
		if !owned {
			continue
		}
		s, e := manager.OpenService(name)
		if e != nil {
			return rejected
		}
		status, e := s.Query()
		if e != nil {
			s.Close()
			return rejected
		}
		if status.State != svc.Stopped {
			if _, e = s.Control(svc.Stop); e != nil {
				s.Close()
				return rejected
			}
			if waitService(s, svc.Stopped, 35*time.Second) != nil {
				s.Close()
				return rejected
			}
		}
		s.Close()
	}
	if removeTask(m) != nil {
		return rejected
	}
	for len(m.Services) > 0 {
		name := m.Services[0]
		s, e := manager.OpenService(name)
		if e != nil {
			return rejected
		}
		if m.begin("service-delete") != nil {
			s.Close()
			return rejected
		}
		e = s.Delete()
		s.Close()
		if e != nil {
			return rejected
		}
		m.Services = m.Services[1:]
		if m.committed() != nil {
			return rejected
		}
	}
	if removeAccount(m) != nil {
		return rejected
	}
	if filepath.WalkDir(m.Install, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return rejected
		}
		attrs, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if e != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return rejected
		}
		return nil
	}) != nil {
		return rejected
	}
	if os.RemoveAll(m.Install) != nil {
		return rejected
	}
	return nil
}

// 本 manifest 必须是本次 SYSTEM 创建的 protected 普通文件；不能采纳其它主体伪造的清理指令。
func protectedManifest(path string) error {
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return rejected
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return rejected
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return rejected
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return rejected
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return rejected
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 {
		return rejected
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return rejected
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != "S-1-5-18" && sid != "S-1-5-32-544" {
			return rejected
		}
	}
	return nil
}
