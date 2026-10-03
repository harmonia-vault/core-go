//go:build darwin

package macosservice

import (
	"strings"
	"testing"
)

func TestV6DisabledProjectionStrictTargetOnly(t *testing.T) {
	l := paths(Target{UID: 501}).Label
	good := []byte("disabled services = {\n\t\"unrelated.synthetic\" => false\n\t\"" + l + "\" => true\n}\n")
	present, value, e := disabledStatus(good, 0, l)
	if e != nil || !present || !value {
		t.Fatal(present, value, e)
	}
	present, _, e = disabledStatus(good, 0, "different.synthetic")
	if e != nil || present {
		t.Fatal(present, e)
	}
	for _, body := range []string{string(good) + "extra", strings.Replace(string(good), " => true", " => 1", 1), strings.Replace(string(good), "}\n", "\""+l+"\" => false\n}\n", 1), "permission denied", strings.Repeat("x", (256<<10)+1)} {
		if _, _, e = disabledStatus([]byte(body), 0, l); e == nil {
			t.Fatal("非规范/重复/超限投影被当成absence")
		}
	}
	if _, _, e = disabledStatus(good, 1, l); e == nil {
		t.Fatal("命令失败被当成absence")
	}
}
func TestV6ObservedJobRequiresFullIdentityAndNonStartingState(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	l := paths(target)
	text := knownJobWithPID(target, "431")
	text = strings.Replace(text, "type = LaunchDaemon", "type = LaunchDaemon\nstate = running", 1)
	if s, e := observedJob([]byte(text), 0, l, target); e != nil || s.PID != 431 || s.State != matching {
		t.Fatal(s, e)
	}
	noPID := strings.Replace(text, "pid = 431\n", "", 1)
	if s, e := observedJob([]byte(noPID), 0, l, target); e != nil || !s.StableNoPID || s.PID != 0 {
		t.Fatal(s, e)
	}
	for _, bad := range []string{strings.Replace(text, "state = running", "state = starting", 1), strings.Replace(text, "state = running\n", "", 1), strings.Replace(text, "pid = 431", "pid = 0", 1), strings.Replace(noPID, "state = running", "state = running\nstate = waiting", 1), strings.Replace(noPID, "username = synthetic", "username = root", 1)} {
		if _, e := observedJob([]byte(bad), 0, l, target); e == nil {
			t.Fatal("未知/启动中服务被认为owner已退出")
		}
	}
}
