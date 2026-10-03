//go:build darwin

package macosservice

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const v7ChildMarker = "harmonia-v7-synthetic-command-child"

func TestV7BoundedCommandChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != v7ChildMarker {
		return
	}
	mode := os.Args[len(os.Args)-1]
	l := paths(Target{UID: 501})
	diagnostic := "Bad request.\nCould not find service \"" + l.Label + "\" in domain for system\n"
	switch mode {
	case "stderr-absent":
		fmt.Fprint(os.Stderr, diagnostic)
		os.Exit(113)
	case "unknown":
		fmt.Fprint(os.Stderr, "permission denied\n")
		os.Exit(1)
	case "other-label":
		fmt.Fprint(os.Stderr, strings.ReplaceAll(diagnostic, l.Label, "unrelated.synthetic"))
		os.Exit(113)
	case "stdout-conflict":
		fmt.Fprint(os.Stdout, "conflicting output\n")
		fmt.Fprint(os.Stderr, diagnostic)
		os.Exit(113)
	case "stdout-overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 1025))
		os.Exit(113)
	case "stderr-overflow":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 1025))
		os.Exit(113)
	case "valid-job", "success-stderr":
		text := knownJobWithPID(Target{UserName: "synthetic", UID: 501, GID: 20}, "431")
		text = strings.Replace(text, "type = LaunchDaemon", "type = LaunchDaemon\nstate = running", 1)
		fmt.Fprint(os.Stdout, text)
		if mode == "success-stderr" {
			fmt.Fprint(os.Stderr, "unrecognized warning\n")
		}
		os.Exit(0)
	case "cancel":
		time.Sleep(10 * time.Second)
		os.Exit(113)
	}
	os.Exit(88)
}
func TestV7StderrOnlyAbsentThroughActualChildProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, e := commandBounded(ctx, 1024, os.Args[0], "-test.run=^TestV7BoundedCommandChild$", "--", v7ChildMarker, "stderr-absent")
	if e != nil {
		t.Fatal(e)
	}
	s, e := observedCommand(result, paths(Target{UID: 501}), Target{UserName: "synthetic", UID: 501, GID: 20})
	if e != nil || s.State != absent {
		t.Fatal("stderr-only官方absence经真实pipe丢失", e)
	}
}

func TestV7CommandBoundariesThroughActualChild(t *testing.T) {
	for _, mode := range []string{"valid-job", "success-stderr", "unknown", "other-label", "stdout-conflict", "stdout-overflow", "stderr-overflow", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 5 * time.Second
			if mode == "cancel" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			result, e := commandBounded(ctx, 1024, os.Args[0], "-test.run=^TestV7BoundedCommandChild$", "--", v7ChildMarker, mode)
			if e == nil {
				_, e = observedCommand(result, paths(Target{UID: 501}), Target{UserName: "synthetic", UID: 501, GID: 20})
			}
			if mode == "valid-job" {
				if e != nil {
					t.Fatal("正常完整身份被拒绝", e)
				}
			} else if e == nil {
				t.Fatal("未知/冲突/超限/取消被当absence", mode)
			}
		})
	}
}
func TestV7OfficialAbsentSingleSyntheticHostLabel(t *testing.T) {
	l := paths(Target{UID: 501})
	l.Label = "org.harmonia-vault.synthetic-v7-ea4b7d108c2649fbb98b13930ea28063"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, e := commandBounded(ctx, 64<<10, "/bin/launchctl", "print", "system/"+l.Label)
	if e != nil {
		t.Fatal("只读官方单合成label探针失败", e)
	}
	if result.exit != 113 || len(result.stdout) != 0 || len(result.stderr) == 0 {
		t.Fatal("官方探针未观察到明确stderr-only absence")
	}
	s, e := observedCommand(result, l, Target{UserName: "synthetic", UID: 501, GID: 20})
	if e != nil || s.State != absent {
		t.Fatal("官方stderr诊断未正确投影", e)
	}
}
