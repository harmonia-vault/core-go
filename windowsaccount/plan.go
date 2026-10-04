// Package windowsaccount 定义标准SCM普通用户服务的独立候选；正式CLI默认门槛仍关闭。
package windowsaccount

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/harmonia-vault/core-go/platform"
)

var ErrPlan = errors.New("windows_account_service_plan_rejected")
var ErrIdentity = errors.New("windows_account_service_identity_rejected")
var ErrUncertain = errors.New("windows_account_service_operation_requires_review")

const ServiceLogonRight = "SeServiceLogonRight"
const DenyServiceLogonRight = "SeDenyServiceLogonRight"

var localName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,19}$`)

// Plan不保存密码。安装时通过单独可清零buffer交给正常CreateService。
type Plan struct {
	TargetSID  string `json:"targetSID"`
	LocalUser  string `json:"localUser"`
	BinaryPath string `json:"binaryPath"`
	ConfigPath string `json:"configPath"`
}

func (p Plan) Name() string {
	sum := sha256.Sum256([]byte(p.TargetSID))
	return "HarmoniaUser-" + hex.EncodeToString(sum[:6])
}
func (p Plan) InstallDirectory() string { return `C:\Program Files\Harmonia\` + p.Name() }
func (p Plan) StateDirectory() string   { return `C:\ProgramData\HarmoniaUser\` + p.Name() + `\vault` }
func (p Plan) AccountName() string      { return `.\` + p.LocalUser }
func (p Plan) Validate() error {
	if !platform.ValidSID(p.TargetSID) || !localName.MatchString(p.LocalUser) || strings.HasSuffix(p.LocalUser, ".") {
		return ErrPlan
	}
	// 固定安装布局，配置与映像不能由普通用户/IPC指定其它文件。
	root := `C:\Program Files\Harmonia\` + p.Name() + `\`
	if p.BinaryPath != root+"harmonia.exe" || p.ConfigPath != root+"service.json" {
		return ErrPlan
	}
	return nil
}

// RightReceipt仅记录权限变化的归属，不包含用户凭据。
// DirectBefore/After来自LSA点名查询；有效拒绝策略永远不自动删除。
type RightReceipt struct {
	TargetSID      string `json:"targetSID"`
	DirectBefore   bool   `json:"directBefore"`
	AddedByInstall bool   `json:"addedByInstall"`
}

func (r RightReceipt) MayRemove(currentSID string, directNow bool, otherServicesUsingAccount int, serviceRemoved bool) bool {
	return platform.ValidSID(r.TargetSID) && currentSID == r.TargetSID && !r.DirectBefore && r.AddedByInstall && directNow && otherServicesUsingAccount == 0 && serviceRemoved
}

type CreateResult struct {
	Created    bool   `json:"created"`
	Configured bool   `json:"configured"`
	Stage      string `json:"stage"`
	Code       uint32 `json:"code,omitempty"`
}

// CreateJournal必须先持久保存精确资源意图。此回调失败就不调用SCM。
// 已Created但Configured为false时服务保持disabled，必须按实际资源审阅收尾。
type CreateJournal interface {
	BeforeCreate(Plan) error
	AfterCreate(Plan, CreateResult) error
}

// 使用调用者专用UTF16 buffer，不制造密码string副本，所有路径均清零。
func consumePassword(password []uint16, use func(*uint16) CreateResult) CreateResult {
	defer clear(password)
	if len(password) < 2 || len(password) > 257 || password[len(password)-1] != 0 || use == nil {
		return CreateResult{Stage: "password-invalid"}
	}
	for _, unit := range password[:len(password)-1] {
		if unit == 0 {
			return CreateResult{Stage: "password-invalid"}
		}
	}
	return use(&password[0])
}
