package linuxinstall

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

const maxSystemctlOutput = 16384
const showProperties = "Id,Names,LoadState,ActiveState,SubState,MainPID,ControlGroup,FragmentPath,DropInPaths,UnitFileState,Triggers,TriggeredBy,Result,ExecMainCode,ExecMainStatus"

type UnitState struct {
	ID             string
	LoadState      string
	ActiveState    string
	SubState       string
	MainPID        uint32
	ControlGroup   string
	FragmentPath   string
	UnitFileState  string
	Result         string
	ExecMainCode   uint32
	ExecMainStatus uint32
}

func ParseUnitState(p Plan, data []byte) (UnitState, error) {
	if p.Validate() != nil || len(data) == 0 || len(data) > maxSystemctlOutput || bytes.ContainsAny(data, "\x00\r") {
		return UnitState{}, ErrState
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return UnitState{}, ErrState
		}
		if _, ok = fields[k]; ok {
			return UnitState{}, ErrState
		}
		fields[k] = v
	}
	want := strings.Split(showProperties, ",")
	if len(fields) != len(want) {
		return UnitState{}, ErrState
	}
	for _, k := range want {
		if _, ok := fields[k]; !ok {
			return UnitState{}, ErrState
		}
	}
	if fields["Id"] != p.UnitName || fields["Names"] != p.UnitName || fields["DropInPaths"] != "" || fields["Triggers"] != "" || fields["TriggeredBy"] != "" {
		return UnitState{}, ErrConflict
	}
	pid, err := strconv.ParseUint(fields["MainPID"], 10, 32)
	if err != nil || strconv.FormatUint(pid, 10) != fields["MainPID"] {
		return UnitState{}, ErrState
	}
	code, err := strconv.ParseUint(fields["ExecMainCode"], 10, 32)
	if err != nil || strconv.FormatUint(code, 10) != fields["ExecMainCode"] {
		return UnitState{}, ErrState
	}
	status, err := strconv.ParseUint(fields["ExecMainStatus"], 10, 32)
	if err != nil || strconv.FormatUint(status, 10) != fields["ExecMainStatus"] {
		return UnitState{}, ErrState
	}
	s := UnitState{ID: fields["Id"], LoadState: fields["LoadState"], ActiveState: fields["ActiveState"], SubState: fields["SubState"], MainPID: uint32(pid), ControlGroup: fields["ControlGroup"], FragmentPath: fields["FragmentPath"], UnitFileState: fields["UnitFileState"], Result: fields["Result"], ExecMainCode: uint32(code), ExecMainStatus: uint32(status)}
	if s.ControlGroup != "" && s.ControlGroup != "/system.slice/"+p.UnitName {
		return UnitState{}, ErrConflict
	}
	if s.LoadState == "not-found" {
		if s.FragmentPath != "" || s.UnitFileState != "" || s.MainPID != 0 || s.ControlGroup != "" || s.ActiveState != "inactive" || s.SubState != "dead" {
			return UnitState{}, ErrState
		}
		return s, nil
	}
	if s.LoadState != "loaded" || s.FragmentPath != p.UnitPath {
		return UnitState{}, ErrConflict
	}
	if s.UnitFileState != "enabled" && s.UnitFileState != "disabled" {
		return UnitState{}, ErrConflict
	}
	switch s.ActiveState {
	case "active":
		if s.SubState != "running" || s.MainPID == 0 {
			return UnitState{}, ErrState
		}
	case "inactive":
		if s.SubState != "dead" || s.MainPID != 0 {
			return UnitState{}, ErrState
		}
	case "failed":
		if s.SubState != "failed" || s.MainPID != 0 {
			return UnitState{}, ErrState
		}
	default:
		return UnitState{}, ErrBusy
	}
	return s, nil
}
func (s UnitState) Stopped() bool {
	return (s.ActiveState == "inactive" && s.SubState == "dead" || s.ActiveState == "failed" && s.SubState == "failed") && s.MainPID == 0
}
func (s UnitState) NormalStop() bool {
	return s.ActiveState == "inactive" && s.SubState == "dead" && s.MainPID == 0 && (s.LoadState == "not-found" || s.Result == "success" && s.ExecMainCode <= 1 && s.ExecMainStatus == 0)
}

type boundedOutput struct {
	b     bytes.Buffer
	limit int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.b.Len() {
		return 0, ErrState
	}
	return w.b.Write(p)
}

// ShowUnit 只读 system manager 固定属性；不以继承 PATH 查找程序或转发宿主 env。
func ShowUnit(ctx context.Context, p Plan) (UnitState, error) {
	if p.Validate() != nil {
		return UnitState{}, ErrPlan
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all", "--property="+showProperties, p.UnitName)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out = boundedOutput{limit: maxSystemctlOutput}
	var discard = boundedOutput{limit: maxSystemctlOutput}
	cmd.Stdout = &out
	cmd.Stderr = &discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return UnitState{}, ctx.Err()
		}
		return UnitState{}, ErrState
	}
	return ParseUnitState(p, out.b.Bytes())
}

// CheckDrained 除 MainPID=0 外还复查固定 control group 的所有后代。
// stop 命令成功、甚至 SIGKILL 后 inactive，均不能代替这一步与后续 Vault/IPClock。
func CheckDrained(ctx context.Context, p Plan) error {
	s, err := ShowUnit(ctx, p)
	if err != nil {
		return err
	}
	if !s.Stopped() {
		return ErrBusy
	}
	if !s.NormalStop() {
		return ErrState
	}
	return checkCgroupDrained(ctx, "/system.slice/"+p.UnitName)
}

func parseCgroupProcesses(data []byte) error {
	if len(data) > 4096 {
		return ErrState
	}
	items := strings.Fields(string(data))
	for _, s := range items {
		if !decimalID(s, true) {
			return ErrState
		}
	}
	if len(items) > 0 {
		return ErrBusy
	}
	return nil
}
