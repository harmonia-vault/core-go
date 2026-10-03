// Package linuxinstall 定义 Linux 单 UID 安装器的固定文件与恢复边界。
// 正式协调器仍为实验性候选；Linux 内核/systemd 联合验收另在隔离 VM 执行。
package linuxinstall

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/harmonia-vault/core-go/platform"
)

var (
	ErrPlan        = errors.New("linux_install_plan_invalid")
	ErrConflict    = errors.New("linux_install_conflict")
	ErrState       = errors.New("linux_install_state_invalid")
	ErrBusy        = errors.New("linux_install_owner_busy")
	ErrPermission  = errors.New("linux_install_permissions_invalid")
	ErrPersistence = errors.New("linux_install_persistence_failed")
	ErrUnsupported = errors.New("linux_install_dependency_unavailable")
)

const AdminDirectory = "/var/lib/harmonia-installer"
const PlanSchema = "harmonia/linux-install-plan/v1"

var userName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var installationID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Input struct {
	UserName     string `json:"userName"`
	UID          string `json:"uid"`
	GID          string `json:"gid"`
	BinarySource string `json:"binarySource"`
	BinarySHA256 string `json:"binarySha256"`
	CASource     string `json:"caSource,omitempty"`
	CASHA256     string `json:"caSha256,omitempty"`
}

type Plan struct {
	Schema           string `json:"schema"`
	Input            Input  `json:"input"`
	UnitName         string `json:"unitName"`
	UnitPath         string `json:"unitPath"`
	ProgramDirectory string `json:"programDirectory"`
	BinaryPath       string `json:"binaryPath"`
	CAPath           string `json:"caPath,omitempty"`
	StateDirectory   string `json:"stateDirectory"`
	ReceiptPath      string `json:"receiptPath"`
	JournalPath      string `json:"journalPath"`
	GuardPath        string `json:"guardPath"`
	EnableLink       string `json:"enableLink"`
}

func decimalID(s string, nonzero bool) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && (!nonzero || n != 0) && strconv.FormatUint(n, 10) == s
}
func absoluteClean(s string) bool {
	return len(s) <= 4096 && filepath.IsAbs(s) && filepath.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n") && s != "/"
}
func NewPlan(in Input) (Plan, error) {
	if !userName.MatchString(in.UserName) || in.UserName == "root" || !decimalID(in.UID, true) || !decimalID(in.GID, true) || !absoluteClean(in.BinarySource) || !digest.MatchString(in.BinarySHA256) {
		return Plan{}, ErrPlan
	}
	if (in.CASource == "") != (in.CASHA256 == "") || in.CASource != "" && (!absoluteClean(in.CASource) || !digest.MatchString(in.CASHA256)) {
		return Plan{}, ErrPlan
	}
	u := in.UID
	p := Plan{Schema: PlanSchema, Input: in, UnitName: "harmonia-user-" + u + ".service", ProgramDirectory: "/usr/local/lib/harmonia/" + u, StateDirectory: "/var/lib/harmonia/" + u, ReceiptPath: AdminDirectory + "/" + u + ".installation.json", JournalPath: AdminDirectory + "/" + u + ".uninstall.json", GuardPath: AdminDirectory + "/" + u + ".uninstalling"}
	p.UnitPath = "/etc/systemd/system/" + p.UnitName
	p.BinaryPath = p.ProgramDirectory + "/harmonia"
	p.EnableLink = "/etc/systemd/system/multi-user.target.wants/" + p.UnitName
	if in.CASource != "" {
		p.CAPath = p.ProgramDirectory + "/ca.pem"
	}
	return p, nil
}
func (p Plan) Validate() error {
	want, err := NewPlan(p.Input)
	if err != nil || p != want {
		return ErrPlan
	}
	return nil
}
func (p Plan) Unit() (platform.ServiceTemplate, error) {
	if err := p.Validate(); err != nil {
		return platform.ServiceTemplate{}, err
	}
	t, err := platform.Systemd(platform.ServiceConfig{UserName: p.Input.UserName, UserID: p.Input.UID, BinaryPath: p.BinaryPath, StateDirectory: p.StateDirectory, CAFile: p.CAPath, Interval: "2s"})
	if err != nil {
		return platform.ServiceTemplate{}, ErrPlan
	}
	extra := "RequiresMountsFor=" + p.StateDirectory + "\nConditionPathExists=!" + p.GuardPath + "\n"
	t.Content = bytes.Replace(t.Content, []byte("[Unit]\n"), []byte("[Unit]\n"+extra), 1)
	return t, nil
}

// 未接通依赖时绝不默认成功；这两条动作必须用已审核 binary 在目标 UID 下执行。
type EnrollmentInspector interface {
	CheckEnrollment(context.Context, Plan) error
}
type OfflineLogout interface {
	LogoutOffline(context.Context, Plan) error
}
type ClosedDependencies struct{}

func (ClosedDependencies) CheckEnrollment(context.Context, Plan) error { return ErrUnsupported }
func (ClosedDependencies) LogoutOffline(context.Context, Plan) error   { return ErrUnsupported }
