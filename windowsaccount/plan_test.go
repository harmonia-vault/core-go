package windowsaccount

import (
	"encoding/json"
	"strings"
	"testing"
)

func testPlan() Plan {
	p := Plan{TargetSID: "S-1-5-21-111-222-333-1001", LocalUser: "harmonia-test"}
	root := `C:\Program Files\Harmonia\` + p.Name() + `\`
	p.BinaryPath = root + "harmonia.exe"
	p.ConfigPath = root + "service.json"
	return p
}
func TestPlanBindsLocalAccountAndFixedResources(t *testing.T) {
	p := testPlan()
	if p.Validate() != nil {
		t.Fatal("合法计划被拒绝")
	}
	for _, edit := range []func(*Plan){func(p *Plan) { p.LocalUser = `domain\user` }, func(p *Plan) { p.LocalUser = "test\n" }, func(p *Plan) { p.TargetSID = "S-1-5-18" }, func(p *Plan) { p.BinaryPath = `C:\Users\test\harmonia.exe` }, func(p *Plan) { p.ConfigPath += `:stream` }} {
		bad := p
		edit(&bad)
		if bad.Validate() == nil {
			t.Fatal("非固定普通用户计划被接受")
		}
	}
	b, _ := json.Marshal(p)
	if strings.Contains(strings.ToLower(string(b)), "password") {
		t.Fatal("计划包含密码字段")
	}
}
func TestRightRemovalRequiresExactOwnershipAndNoOtherService(t *testing.T) {
	r := RightReceipt{TargetSID: testPlan().TargetSID, AddedByInstall: true}
	if !r.MayRemove(r.TargetSID, true, 0, true) {
		t.Fatal("独占新增权限不能收尾")
	}
	if r.MayRemove(r.TargetSID, true, 1, true) || r.MayRemove(r.TargetSID, true, -1, true) || r.MayRemove(r.TargetSID, true, 0, false) || r.MayRemove("S-1-5-21-111-222-333-1002", true, 0, true) {
		t.Fatal("撤销越过归属/服务检查")
	}
	r.DirectBefore = true
	if r.MayRemove(r.TargetSID, true, 0, true) {
		t.Fatal("删除安装前既有权限")
	}
}
func TestPasswordClearedOnFailureAndSuccessWithoutJournalStorage(t *testing.T) {
	for _, scenario := range []string{"success", "failure", "malformed"} {
		malformed := scenario == "malformed"
		pw := []uint16{'s', 'y', 'n', 't', 'h', 'e', 't', 'i', 'c', 0}
		if malformed {
			pw[2] = 0
		}
		called := false
		result := consumePassword(pw, func(ptr *uint16) CreateResult {
			called = true
			if *ptr != 's' {
				t.Fatal("未传原可清零buffer")
			}
			if scenario == "success" {
				return CreateResult{Stage: "synthetic-created", Created: true, Configured: true}
			}
			return CreateResult{Stage: "synthetic-call-failed", Code: 5}
		})
		if called == malformed || (scenario == "failure" && result.Code != 5) || (scenario == "success" && !result.Configured) {
			t.Fatal("错误路径未保留固定结果")
		}
		for _, unit := range pw {
			if unit != 0 {
				t.Fatal("密码buffer未清零")
			}
		}
	}
}
