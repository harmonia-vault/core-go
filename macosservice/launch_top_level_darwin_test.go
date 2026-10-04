//go:build darwin

package macosservice

import (
	"strings"
	"testing"
)

func actualNestedIdentity(t Target) string {
	text := knownJobWithPID(t, "431")
	text = strings.Replace(text, "type = LaunchDaemon", "type = LaunchDaemon\nstate = running", 1)
	return strings.TrimSuffix(text, "}") + "resource coalition = {\ntype = resource\nstate = active\npid = 999\n}\njetsam coalition = {\ntype = jetsam\nstate = active\n}\n}"
}

func TestNestedLaunchIdentityAndObservedPID(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	l, text := paths(target), actualNestedIdentity(target)
	if launchState([]byte(text), 0, l, target) != matching {
		t.Fatal("合法嵌套被误判未知")
	}
	s, err := observedJob([]byte(text), 0, l, target)
	if err != nil || s.State != matching || s.PID != 431 || s.StableNoPID {
		t.Fatal("observedJob未使用顶层身份/PID", err)
	}
	if pid, err := jobPID([]byte(text), l, target); err != nil || pid != 431 {
		t.Fatal("controlledPID受到nested污染", err)
	}
}

func TestNestedIdentityDoesNotRelaxMismatchOrStarting(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	l, text := paths(target), actualNestedIdentity(target)
	for _, bad := range []string{
		strings.Replace(text, "username = synthetic", "username = root", 1),
		strings.Replace(text, "type = LaunchDaemon", "type = LaunchDaemon\ntype = LaunchDaemon", 1),
		strings.Replace(text, "\n--local-user\n501", "\n--local-user\n502", 1),
		strings.TrimSuffix(text, "}"), text + "\n}",
	} {
		if launchState([]byte(bad), 0, l, target) != unknown {
			t.Fatal("错误身份/参数/括号被放宽")
		}
		if _, err := observedJob([]byte(bad), 0, l, target); err == nil {
			t.Fatal("observedJob接受未知材料")
		}
	}
	starting := strings.Replace(text, "state = running", "state = starting", 1)
	if _, err := observedJob([]byte(starting), 0, l, target); err == nil {
		t.Fatal("启动中服务被认为stable")
	}
	noPID := strings.Replace(text, "pid = 431\n", "", 1)
	if s, err := observedJob([]byte(noPID), 0, l, target); err != nil || !s.StableNoPID || s.PID != 0 {
		t.Fatal("合法无PID状态未保持", err)
	}
}
