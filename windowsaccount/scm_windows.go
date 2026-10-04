//go:build windows

package windowsaccount

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func errorCode(err error) uint32 {
	var code syscall.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return uint32(windows.ERROR_GEN_FAILURE)
}

// CreateDisabled只能创建新服务；不会覆盖、启动、启用自动启动或授予LSA权限。
// caller须已完成受保护二进制/config安装、权限基线与根审阅。
// 密码由已授权输入/helper交给SCM，其LSA存储属于正常Windows服务行为。
func CreateDisabled(p Plan, password []uint16, journal CreateJournal) (result CreateResult) {
	defer clear(password)
	if p.Validate() != nil || journal == nil {
		return CreateResult{Stage: "plan-rejected"}
	}
	// 在修改前用SAM名字再核exact SID，拒绝重名/替换账号。
	if verifyLocalPlanAccount(p) != nil {
		return CreateResult{Stage: "identity-rejected"}
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return CreateResult{Stage: "open-scm", Code: errorCode(err)}
	}
	defer windows.CloseServiceHandle(manager)
	// 所有字段验证和SCM句柄取得后才写意图；CreateService本身拒绝同名资源。
	if err = journal.BeforeCreate(p); err != nil {
		return CreateResult{Stage: "intent-not-durable"}
	}
	result = consumePassword(password, func(pw *uint16) CreateResult {
		binary := `"` + p.BinaryPath + `" daemon-user-service --config "` + p.ConfigPath + `"`
		service, err := windows.CreateService(manager, windows.StringToUTF16Ptr(p.Name()), windows.StringToUTF16Ptr(p.Name()), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_CHANGE_CONFIG|windows.READ_CONTROL, windows.SERVICE_WIN32_OWN_PROCESS, windows.SERVICE_DISABLED, windows.SERVICE_ERROR_NORMAL, windows.StringToUTF16Ptr(binary), nil, nil, nil, windows.StringToUTF16Ptr(p.AccountName()), pw)
		if err != nil {
			return CreateResult{Stage: "create-disabled", Code: errorCode(err)}
		}
		defer windows.CloseServiceHandle(service)
		created := CreateResult{Created: true, Stage: "restrict-privileges"}
		// 只保留既有遍历检查权限；不添加Backup/Restore/Impersonate等权限。
		privileges := append(windows.StringToUTF16("SeChangeNotifyPrivilege"), 0)
		info := struct{ Names *uint16 }{&privileges[0]}
		if err = windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info))); err != nil {
			created.Code = errorCode(err)
			return created
		}
		// 此SID作为组标识本SCM服务，未把进程用户改成虚拟账号。
		sidType := uint32(windows.SERVICE_SID_TYPE_UNRESTRICTED)
		if err = windows.ChangeServiceConfig2(service, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType))); err != nil {
			created.Stage = "service-sid"
			created.Code = errorCode(err)
			return created
		}
		created.Configured = true
		created.Stage = "disabled-configured"
		return created
	})
	if err = journal.AfterCreate(p, result); err != nil {
		result.Configured = false
		result.Stage = "result-not-durable"
	}
	return result
}
