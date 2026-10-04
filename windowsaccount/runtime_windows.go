//go:build windows

package windowsaccount

import (
	"github.com/harmonia-vault/core-go/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// VerifyOwnService仅查询本进程身份，不登录、复制token、impersonate或加载profile。
func VerifyOwnService(p Plan) error {
	if p.Validate() != nil {
		return ErrPlan
	}
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return ErrIdentity
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != p.TargetSID || token.IsElevated() {
		return ErrIdentity
	}
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session != 0 {
		return ErrIdentity
	}
	serviceSID, _, _, err := windows.LookupSID("", `NT SERVICE\`+p.Name())
	if err != nil {
		return ErrIdentity
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return ErrIdentity
	}
	serviceGroup, exactServiceGroup := false, false
	for _, group := range groups.AllGroups() {
		// 拒绝管理员成员，即使是deny-only也不能把该用户作为普通测试主体。
		if group.Sid.String() == "S-1-5-32-544" {
			return ErrIdentity
		}
		if group.Attributes&windows.SE_GROUP_ENABLED == 0 || group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		serviceGroup = serviceGroup || group.Sid.String() == "S-1-5-6"
		exactServiceGroup = exactServiceGroup || group.Sid.Equals(serviceSID)
	}
	if !serviceGroup || !exactServiceGroup {
		return ErrIdentity
	}
	return nil
}

// OpenOwnEnvironment复用正式点名注册表provider；SCM负责用户profile。
// 失败时不回退SYSTEM HKCU，也不自行取得token或加载其它hive。
func OpenOwnEnvironment(p Plan) (platform.UserEnvironmentStore, error) {
	if err := VerifyOwnService(p); err != nil {
		return nil, err
	}
	return platform.OpenUserRegistry(p.TargetSID)
}
