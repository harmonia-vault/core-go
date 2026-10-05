//go:build windows

package main

import (
	"github.com/harmonia-vault/core-go/internal/wincom"
	"github.com/harmonia-vault/core-go/windowsservice"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func createTaskFolder(m *manifest) error {
	scheduler, e := wincom.Open()
	if e != nil {
		return rejected
	}
	defer scheduler.Close()
	top, e := scheduler.Object(scheduler.Root, "GetFolder", `\`)
	if e != nil {
		return rejected
	}
	root, e := scheduler.Object(scheduler.Root, "GetFolder", `\Harmonia`)
	if e != nil {
		if m.begin("scheduler-root-create") != nil {
			return rejected
		}
		root, e = scheduler.Object(top, "CreateFolder", "Harmonia", adminFile+`(A;;GRGX;;;BU)`)
		if e != nil {
			return rejected
		}
		m.RootCreated = true
		if m.committed() != nil {
			return rejected
		}
	}
	c := m.config()
	if _, e = scheduler.Object(scheduler.Root, "GetFolder", c.TaskFolder()); e == nil {
		return rejected
	}
	if m.begin("scheduler-folder-create") != nil {
		return rejected
	}
	if _, e = scheduler.Object(root, "CreateFolder", "Profile-"+c.Tag(), adminFile+`(A;;GRGWGX;;;`+m.TargetSID+`)`); e != nil {
		return rejected
	}
	m.FolderCreated = true
	m.TaskFolder = c.TaskFolder()
	m.Phase = "pre-register"
	return m.committed()
}
func lockTask(m *manifest) error {
	scheduler, e := wincom.Open()
	if e != nil {
		return rejected
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", m.TaskFolder)
	if e != nil {
		return rejected
	}
	tasks, e := scheduler.Object(folder, "GetTasks", 1)
	if e != nil {
		return rejected
	}
	count, e := scheduler.Number(tasks, "Count")
	if e != nil || count != 1 {
		return rejected
	}
	children, e := scheduler.Object(folder, "GetFolders", 0)
	if e != nil {
		return rejected
	}
	count, e = scheduler.Number(children, "Count")
	if e != nil || count != 0 {
		return rejected
	}
	task, e := scheduler.Object(folder, "GetTask", "Token")
	if e != nil {
		return rejected
	}
	doc, e := scheduler.PropertyString(task, "Xml")
	if e != nil || m.config().ValidateTask([]byte(doc)) != nil {
		return rejected
	}
	descriptor := adminFile + `(A;;GRGX;;;` + m.TargetSID + `)`
	if _, e = scheduler.Call(task, "SetSecurityDescriptor", descriptor, 16); e != nil {
		return rejected
	}
	if _, e = scheduler.Call(folder, "SetSecurityDescriptor", descriptor, 0); e != nil {
		return rejected
	}
	return nil
}
func taskCompleted(m *manifest) error {
	scheduler, e := wincom.Open()
	if e != nil {
		return rejected
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", m.TaskFolder)
	if e != nil {
		return rejected
	}
	task, e := scheduler.Object(folder, "GetTask", "Token")
	if e != nil {
		return rejected
	}
	result, e := scheduler.Number(task, "LastTaskResult")
	if e != nil || result != 0 {
		return rejected
	}
	return nil
}
func removeTask(m *manifest) error {
	if !m.FolderCreated {
		return nil
	}
	if m.TaskFolder != m.config().TaskFolder() {
		return rejected
	}
	scheduler, e := wincom.Open()
	if e != nil {
		return rejected
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", m.TaskFolder)
	if e != nil {
		return rejected
	}
	tasks, e := scheduler.Object(folder, "GetTasks", 1)
	if e != nil {
		return rejected
	}
	count, e := scheduler.Number(tasks, "Count")
	if e != nil || count > 1 {
		return rejected
	}
	children, e := scheduler.Object(folder, "GetFolders", 0)
	if e != nil {
		return rejected
	}
	childCount, e := scheduler.Number(children, "Count")
	if e != nil || childCount != 0 {
		return rejected
	}
	if count == 1 {
		task, e := scheduler.Object(folder, "GetTask", "Token")
		if e != nil {
			return rejected
		}
		doc, e := scheduler.PropertyString(task, "Xml")
		if e != nil || m.config().ValidateTask([]byte(doc)) != nil {
			return rejected
		}
		state, err := scheduler.Number(task, "State")
		if err != nil || state < 1 || state > 4 {
			return rejected
		}
		if state == 2 || state == 4 {
			if _, e = scheduler.Call(task, "Stop", 0); e != nil {
				return rejected
			}
		}
		if m.begin("task-delete") != nil {
			return rejected
		}
		if _, e = scheduler.Call(folder, "DeleteTask", "Token", 0); e != nil {
			return rejected
		}
		m.TaskRegistered = false
		if m.committed() != nil {
			return rejected
		}
	}
	root, e := scheduler.Object(scheduler.Root, "GetFolder", `\Harmonia`)
	if e != nil {
		return rejected
	}
	if m.begin("scheduler-folder-delete") != nil {
		return rejected
	}
	if _, e = scheduler.Call(root, "DeleteFolder", "Profile-"+m.config().Tag(), 0); e != nil {
		return rejected
	}
	m.FolderCreated = false
	m.TaskRegistered = false
	if m.committed() != nil {
		return rejected
	}
	if m.RootCreated {
		tasks, e := scheduler.Object(root, "GetTasks", 1)
		if e != nil {
			return rejected
		}
		count, e := scheduler.Number(tasks, "Count")
		if e != nil {
			return rejected
		}
		folders, e := scheduler.Object(root, "GetFolders", 0)
		if e != nil {
			return rejected
		}
		children, e := scheduler.Number(folders, "Count")
		if e != nil {
			return rejected
		}
		if count == 0 && children == 0 {
			top, e := scheduler.Object(scheduler.Root, "GetFolder", `\`)
			if e != nil {
				return rejected
			}
			if m.begin("scheduler-root-delete") != nil {
				return rejected
			}
			if _, e = scheduler.Call(top, "DeleteFolder", "Harmonia", 0); e != nil {
				return rejected
			}
			m.RootCreated = false
			if m.committed() != nil {
				return rejected
			}
		}
	}
	return nil
}

// resolveTaskAbsent 只解除已独立核实的 self-register 未知结果；不注册任务、不启动服务或改 ACL。
// GetTasks(1) 包含隐藏任务；只接受零任务/零子目录，保留原数值错误未记录的历史。
func resolveTaskAbsent(m *manifest, expectedSID string) error {
	return resolveTaskAbsentWithObservation(m, expectedSID, nil)
}

// 此入口仅保存当前已核对 numeric helper 的实际输出；不给未知/其它 PE 回填代码。
// 原 Pending/SAM/hash/Stopped/零任务检查全部在共同路径完成，观察码不作为清理授权依据。
func resolveTaskAbsentXML(m *manifest, expectedSID string) error {
	const reviewedHelper = "3ae0d692ca15d17d93d30f9aaf324a3e35d955e4cadcaaeb78c160a81ef80275"
	if m.ProfileSHA256 != reviewedHelper {
		return rejected
	}
	diagnostic := &taskObservedDiagnostic{Source: "reviewed-guest-output", Stage: "register-task", HelperSHA256: reviewedHelper, HRESULT: 0x80020009, SCODE: 0x8004131a, WCode: 0}
	return resolveTaskAbsentWithObservation(m, expectedSID, diagnostic)
}

func resolveTaskAbsentWithObservation(m *manifest, expectedSID string, observation *taskObservedDiagnostic) error {
	if m.PendingAction != "task-self-register" || m.TargetSID != expectedSID || !m.AccountCreated || !m.ProfileCreated || m.ProfileHRESULT == nil || *m.ProfileHRESULT != 0 || !m.BatchGranted || m.BatchNTSTATUS == nil || *m.BatchNTSTATUS != 0 || m.BatchStatusStage != "lsa-add" || !m.RootCreated || !m.FolderCreated || m.TaskRegistered || len(m.Services) != 2 {
		return rejected
	}
	c := m.config()
	if m.TaskFolder != c.TaskFolder() || m.Services[0] != c.BrokerServiceName() || m.Services[1] != c.SyncServiceName() {
		return rejected
	}
	locked, e := windowsservice.LoadConfig(c.ConfigurationFile)
	if e != nil {
		return rejected
	}
	defer locked.Close()
	if locked.Config != c {
		return rejected
	}
	for _, binary := range []struct{ path, want string }{{c.Executable, m.ProfileSHA256}, {c.SyncExecutable, m.SyncSHA256}} {
		got, e := hash(binary.path)
		if e != nil || got != binary.want {
			return rejected
		}
	}
	manager, e := mgr.Connect()
	if e != nil {
		return rejected
	}
	defer manager.Disconnect()
	for _, name := range m.Services {
		service, e := manager.OpenService(name)
		if e != nil {
			return rejected
		}
		status, e := service.Query()
		service.Close()
		if e != nil || status.State != svc.Stopped {
			return rejected
		}
	}
	scheduler, e := wincom.Open()
	if e != nil {
		return rejected
	}
	defer scheduler.Close()
	folder, e := scheduler.Object(scheduler.Root, "GetFolder", c.TaskFolder())
	if e != nil {
		return rejected
	}
	descriptor, e := scheduler.String(folder, "GetSecurityDescriptor", 7)
	if e != nil {
		return rejected
	}
	sd, e := windows.SecurityDescriptorFromString(descriptor)
	if e != nil {
		return rejected
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || owner.String() != "S-1-5-18" {
		return rejected
	}
	control, _, e := sd.Control()
	if e != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return rejected
	}
	tasks, e := scheduler.Object(folder, "GetTasks", 1)
	if e != nil {
		return rejected
	}
	taskCount, e := scheduler.Number(tasks, "Count")
	if e != nil || taskCount != 0 {
		return rejected
	}
	children, e := scheduler.Object(folder, "GetFolders", 0)
	if e != nil {
		return rejected
	}
	childCount, e := scheduler.Number(children, "Count")
	if e != nil || childCount != 0 {
		return rejected
	}
	m.TaskFailureHistory = append(m.TaskFailureHistory, taskFailure{Stage: "task-self-register", Outcome: "confirmed-not-registered", HRESULTRecorded: false, ObservedDiagnostic: observation, TaskCount: taskCount, ChildFolderCount: childCount, StoppedServiceCount: 2})
	m.Phase = "registration-confirmed-absent"
	return m.committed()
}
