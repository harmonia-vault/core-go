package platform

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// 本文件只让子进程看到明确合成的环境，不扫描宿主环境或运行系统服务。
func cleanupShell(t *testing.T, shell, script string, interactive bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("需要 POSIX shell")
	}
	binary, err := exec.LookPath(shell)
	if err != nil {
		t.Skip(shell + " 不可用")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-c", script}
	if shell == "zsh" {
		args = []string{"-f", "-c", script}
	}
	if interactive {
		switch shell {
		case "bash":
			args = []string{"--noprofile", "--norc", "-i"}
		case "zsh":
			args = []string{"-f", "-i"}
		default:
			t.Fatal("sh 仅承诺显式刷新")
		}
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir(), "TERM=dumb", "PS1=synthetic-prompt> "}
	if interactive {
		cmd.Stdin = strings.NewReader(script)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 错误只报告固定场景、退出结果；不把执行脚本/托管值输出到日志。
		t.Fatalf("合成 shell 场景失败：%v（输出 %d 字节）", err, len(output))
	}
}

func cleanupScope(t *testing.T, dir, shell string, desired map[string]string) (string, string) {
	t.Helper()
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fragment := filepath.Join(dir, "environment.sh")
	data, err := RenderPOSIXFragment(fragment, desired, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fragment, data)
	hook, err := RenderShellHook(shell, fragment)
	if err != nil {
		t.Fatal(err)
	}
	return fragment, hook
}

func cleanupQuote(t *testing.T, text string) string {
	t.Helper()
	quoted, err := ShellQuote(text)
	if err != nil {
		t.Fatal(err)
	}
	return quoted
}

func cleanupPrefix(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("__HARMONIA_%X_", sum[:8])
}

func TestPOSIXUninstallRestoresLoadedShell(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		for _, mode := range []string{"explicit", "prompt"} {
			if shell == "sh" && mode == "prompt" {
				continue
			}
			t.Run(shell+"/"+mode, func(t *testing.T) {
				parent := t.TempDir()
				scope := filepath.Join(parent, "scope")
				malicious := "synthetic'\n$(touch " + filepath.Join(parent, "must-not-exist") + ") `false` $HOME \\\n"
				fragment, hook := cleanupScope(t, scope, shell, map[string]string{"MANAGED": malicious, "NEW_KEY": "synthetic-added", "EMPTY": "synthetic-filled"})
				released, err := RenderPOSIXFragment(fragment, map[string]string{}, []string{"MANAGED", "NEW_KEY", "EMPTY"})
				if err != nil {
					t.Fatal(err)
				}
				release := filepath.Join(parent, "release.sh")
				writeTestFile(t, release, released)
				active, _ := os.ReadFile(fragment)
				reinstall := filepath.Join(parent, "reinstall.sh")
				writeTestFile(t, reinstall, active)
				script := "set -eu\nexport MANAGED='synthetic-original' EMPTY='' UNRELATED='synthetic-keep'\nunset NEW_KEY\n" + hook
				script += "[ \"$MANAGED\" = " + cleanupQuote(t, malicious) + " ] || exit 41\nUNRELATED=synthetic-user-edit\n"
				// logout 已写 release，但这个 shell 尚未消费；卸载随即删除整个 scope。
				script += "/bin/cp " + cleanupQuote(t, release) + " " + cleanupQuote(t, fragment) + "; /bin/rm " + cleanupQuote(t, fragment) + "; /bin/rmdir " + cleanupQuote(t, scope) + "\n"
				if mode == "explicit" {
					script += "harmonia_refresh\n"
				}
				script += "[ \"$MANAGED\" = synthetic-original ] && [ \"${NEW_KEY+x}\" != x ] && [ \"${EMPTY+x}\" = x ] && [ \"$EMPTY\" = '' ] && [ \"$UNRELATED\" = synthetic-user-edit ] || exit 41\n"
				script += "MANAGED=synthetic-after-release\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-after-release ] || exit 41\n"
				// 再安装后必须重新捕获当前原值，不能复活前一次原值或新增项。
				script += "/bin/mkdir " + cleanupQuote(t, scope) + "; /bin/cp " + cleanupQuote(t, reinstall) + " " + cleanupQuote(t, fragment) + "\nharmonia_refresh\n"
				script += "[ \"$MANAGED\" = " + cleanupQuote(t, malicious) + " ] || exit 41\n/bin/rm " + cleanupQuote(t, fragment) + "; /bin/rmdir " + cleanupQuote(t, scope) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-after-release ] && [ \"${NEW_KEY+x}\" != x ] || exit 41\nexit 0\n"
				cleanupShell(t, shell, script, mode == "prompt")
				if _, err := os.Stat(filepath.Join(parent, "must-not-exist")); !os.IsNotExist(err) {
					t.Fatal("值中的命令被执行")
				}
			})
		}
	}
}

func TestPOSIXAbsentFragmentIsNotUninstall(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			parent := t.TempDir()
			scope := filepath.Join(parent, "scope")
			fragment, hook := cleanupScope(t, scope, shell, map[string]string{"MANAGED": "synthetic-cloud", "NEW_KEY": "synthetic-added"})
			script := "set -eu\nMANAGED=synthetic-original\nunset NEW_KEY\n" + hook
			script += "/bin/rm " + cleanupQuote(t, fragment) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-cloud ] && [ \"$NEW_KEY\" = synthetic-added ] || exit 41\n"
			// 明确的本 shell 清理无需读文件；它不是云端注销或磁盘清理命令。
			script += "harmonia_refresh --release\n[ \"$MANAGED\" = synthetic-original ] && [ \"${NEW_KEY+x}\" != x ] || exit 41\nMANAGED=synthetic-local\nharmonia_refresh --release\n[ \"$MANAGED\" = synthetic-local ] || exit 41\n"
			cleanupShell(t, shell, script, false)
		})
	}
}

func TestPOSIXRemainingSymlinkIsNotUninstall(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			parent := t.TempDir()
			scope := filepath.Join(parent, "scope")
			fragment, hook := cleanupScope(t, scope, shell, map[string]string{"MANAGED": "synthetic-cloud"})
			q := func(s string) string { return cleanupQuote(t, s) }
			script := "set -eu\nMANAGED=synthetic-original\n" + hook
			script += "/bin/rm " + q(fragment) + "; /bin/rmdir " + q(scope) + "; /bin/ln -s " + q(filepath.Join(parent, "missing")) + " " + q(scope) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-cloud ] || exit 41\n"
			script += "/bin/rm " + q(scope) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-original ] || exit 41\n"
			cleanupShell(t, shell, script, false)
		})
	}
}

func TestPOSIXIndependentScopeHooks(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			parent := t.TempDir()
			a, ahook := cleanupScope(t, filepath.Join(parent, "a"), shell, map[string]string{"SCOPE_A": "synthetic-a"})
			b, bhook := cleanupScope(t, filepath.Join(parent, "b"), shell, map[string]string{"SCOPE_B": "synthetic-b"})
			script := "set -eu\nSCOPE_A=synthetic-original-a\nSCOPE_B=synthetic-original-b\nUNRELATED=synthetic-keep\n"
			if shell == "bash" {
				script += "PROMPT_COMMAND=()\n"
			}
			script += ahook + bhook + ahook + bhook
			// sh 无 prompt；执行生成的固定 scope 函数，不 eval/枚举函数名。
			refreshA := cleanupPrefix(a) + "REFRESH"
			refreshB := cleanupPrefix(b) + "REFRESH"
			if shell == "bash" {
				script += "[ \"${#PROMPT_COMMAND[@]}\" = 2 ] || exit 41\n"
			}
			if shell == "zsh" {
				script += "[ \"${#precmd_functions[@]}\" = 2 ] || exit 41\n"
			}
			q := func(s string) string { return cleanupQuote(t, s) }
			script += "/bin/rm " + q(a) + "; /bin/rmdir " + q(filepath.Dir(a)) + "\n"
			if shell == "sh" {
				script += refreshA + "\n" + refreshB + "\n"
			}
			script += "[ \"$SCOPE_A\" = synthetic-original-a ] && [ \"$SCOPE_B\" = synthetic-b ] && [ \"$UNRELATED\" = synthetic-keep ] || exit 41\n"
			script += "/bin/rm " + q(b) + "; /bin/rmdir " + q(filepath.Dir(b)) + "\n"
			if shell == "sh" {
				script += refreshA + "\n" + refreshB + "\n"
			}
			script += "[ \"$SCOPE_A\" = synthetic-original-a ] && [ \"$SCOPE_B\" = synthetic-original-b ] || exit 41\n"
			cleanupShell(t, shell, script, shell != "sh")
		})
	}
}

func TestPOSIXMissingParentPreservesLoadedConfiguration(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			scope := filepath.Join(parent, "scope")
			fragment, hook := cleanupScope(t, scope, shell, map[string]string{"MANAGED": "synthetic-cloud"})
			q := func(s string) string { return cleanupQuote(t, s) }
			script := "set -eu\nMANAGED=synthetic-original\n" + hook
			script += "/bin/rm " + q(fragment) + "; /bin/rmdir " + q(scope) + "; /bin/rmdir " + q(parent) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-cloud ] || exit 41\n"
			script += "/bin/mkdir " + q(parent) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-original ] || exit 41\n"
			cleanupShell(t, shell, script, false)
		})
	}
}

func TestPOSIXCleanupRetainsPauseAndReleasesRevocation(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			parent := t.TempDir()
			scope := filepath.Join(parent, "scope")
			fragment, hook := cleanupScope(t, scope, shell, map[string]string{"MANAGED": "synthetic-cloud"})
			paused, err := renderPOSIXFragment(fragment, map[string]string{"MANAGED": "synthetic-cloud"}, nil, true, map[string]uint64{"MANAGED": 1})
			if err != nil {
				t.Fatal(err)
			}
			released, err := renderPOSIXFragment(fragment, map[string]string{}, []string{"MANAGED"}, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			p, r := filepath.Join(parent, "paused.sh"), filepath.Join(parent, "release.sh")
			writeTestFile(t, p, paused)
			writeTestFile(t, r, released)
			q := func(s string) string { return cleanupQuote(t, s) }
			script := "set -eu\nMANAGED=synthetic-original\n" + hook
			// 片段持久时正常 owner 停止或崩溃不会被误当卸载，仍按既有配置纠正。
			script += "MANAGED=synthetic-external\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-cloud ] || exit 41\n"
			script += "/bin/cp " + q(p) + " " + q(fragment) + "\nMANAGED=synthetic-paused-edit\nharmonia_refresh\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-paused-edit ] || exit 41\n"
			script += "/bin/cp " + q(r) + " " + q(fragment) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-original ] || exit 41\nMANAGED=synthetic-after-revoke\n/bin/rm " + q(fragment) + "; /bin/rmdir " + q(scope) + "\nharmonia_refresh\n[ \"$MANAGED\" = synthetic-after-revoke ] || exit 41\n"
			cleanupShell(t, shell, script, false)
		})
	}
}
