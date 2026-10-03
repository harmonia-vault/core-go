package linuxinstall

import (
	"strings"
	"testing"
)

func showFixture(p Plan) string {
	return "Id=" + p.UnitName + "\nNames=" + p.UnitName + "\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=\nFragmentPath=" + p.UnitPath + "\nDropInPaths=\nUnitFileState=disabled\nTriggers=\nTriggeredBy=\nResult=success\nExecMainCode=1\nExecMainStatus=0\n"
}
func TestNormalStopDoesNotMeanKilledOrOwnerDrained(t *testing.T) {
	p := syntheticPlan(t)
	b := showFixture(p)
	s, err := ParseUnitState(p, []byte(b))
	if err != nil || !s.NormalStop() {
		t.Fatalf("normal exit rejected: %v", err)
	}
	for _, c := range []struct{ name, key, value string }{{"timeout", "Result=success", "Result=timeout"}, {"sigkill", "ExecMainCode=1", "ExecMainCode=2"}, {"signalstatus", "ExecMainStatus=0", "ExecMainStatus=9"}, {"failed", "ActiveState=inactive\nSubState=dead", "ActiveState=failed\nSubState=failed"}} {
		t.Run(c.name, func(t *testing.T) {
			s, err := ParseUnitState(p, []byte(strings.Replace(b, c.key, c.value, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if s.NormalStop() {
				t.Fatal("abnormal exit claimed normal drain")
			}
		})
	}
	if parseCgroupProcesses([]byte("23\n")) != ErrBusy || parseCgroupProcesses([]byte("23\n24\n")) != ErrBusy {
		t.Fatal("remaining process accepted")
	}
	if parseCgroupProcesses([]byte("\n")) != nil {
		t.Fatal("empty cgroup rejected")
	}
	if parseCgroupProcesses([]byte("23\nbad\n")) != ErrState || parseCgroupProcesses([]byte("0001\n")) != ErrState {
		t.Fatal("invalid cgroup data accepted")
	}
}
func TestSystemdRejectsAliasesDropinsTransitionsAndForgedOutput(t *testing.T) {
	p := syntheticPlan(t)
	b := showFixture(p)
	cases := []struct{ name, value string }{
		{"duplicate", b + "MainPID=0\n"}, {"dropin", strings.Replace(b, "DropInPaths=", "DropInPaths=/etc/systemd/system/extra.conf", 1)}, {"alias", strings.Replace(b, "Names="+p.UnitName, "Names="+p.UnitName+" alien.service", 1)}, {"trigger", strings.Replace(b, "Triggers=\n", "Triggers=alien.timer\n", 1)}, {"foreignfragment", strings.Replace(b, p.UnitPath, "/usr/lib/systemd/system/alien.service", 1)}, {"starting", strings.Replace(b, "ActiveState=inactive\nSubState=dead", "ActiveState=activating\nSubState=start", 1)}, {"nonzeroPID", strings.Replace(b, "MainPID=0", "MainPID=23", 1)}, {"foreigngroup", strings.Replace(b, "ControlGroup=\n", "ControlGroup=/system.slice/alien.service\n", 1)}, {"newprop", b + "Secret=unused\n"}, {"masked", strings.Replace(b, "UnitFileState=disabled", "UnitFileState=masked", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseUnitState(p, []byte(c.value)); err == nil {
				t.Fatal("unsafe system manager output accepted")
			}
		})
	}
}
