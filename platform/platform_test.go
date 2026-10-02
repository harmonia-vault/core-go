package platform

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/localstate"
)

func pointer(v string) *string { return &v }
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestShellLiteralRestorationAndCorrection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell execution requires POSIX")
	}
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			binary, err := exec.LookPath(shell)
			if err != nil {
				t.Skip(shell + " unavailable")
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			malicious := "synthetic'\n$(touch " + filepath.Join(dir, "must-not-exist") + ") `false` $HOME \\\n"
			active, err := RenderPOSIXFragment("synthetic-shell-test", map[string]string{"MANAGED": malicious, "NEW_KEY": "added", "EMPTY": "managed"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			released, err := RenderPOSIXFragment("synthetic-shell-test", map[string]string{}, []string{"MANAGED", "NEW_KEY", "EMPTY"})
			if err != nil {
				t.Fatal(err)
			}
			a, r := filepath.Join(dir, "active.sh"), filepath.Join(dir, "release.sh")
			writeTestFile(t, a, active)
			writeTestFile(t, r, released)
			aq, _ := ShellQuote(a)
			rq, _ := ShellQuote(r)
			mq, _ := ShellQuote(malicious)
			script := "set -eu\nexport MANAGED='before' UNRELATED='keep' EMPTY=''\nunset NEW_KEY\n. " + aq + "\n[ \"$MANAGED\" = " + mq + " ]\nMANAGED=external-edit\n. " + aq + "\n[ \"$MANAGED\" = " + mq + " ]\nUNRELATED=independent-change\n. " + rq + "\n[ \"$MANAGED\" = before ]\n[ \"${NEW_KEY+x}\" != x ]\n[ \"${EMPTY+x}\" = x ]\n[ \"$EMPTY\" = '' ]\n[ \"$UNRELATED\" = independent-change ]\nMANAGED=after-release\n. " + rq + "\n[ \"$MANAGED\" = after-release ]\n. " + aq + "\n. " + rq + "\n[ \"$MANAGED\" = after-release ]\n"
			command := exec.Command(binary, "-c", script)
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("shell failed: %v %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(dir, "must-not-exist")); !os.IsNotExist(err) {
				t.Fatal("literal executed command")
			}
		})
	}
}
func TestPOSIXPersistenceAndOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "environment.sh")
	p, err := NewPOSIXProvider(path, map[string]string{"MANAGED": "original"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "MANAGED", Value: pointer("cloud")}}); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, []byte(fragmentMarker+"# stale fragment\n"))
	restarted, err := NewPOSIXProvider(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), "export MANAGED='cloud'") {
		t.Fatalf("did not converge after crash: %v", err)
	}
	if err := restarted.Apply(context.Background(), []localstate.Change{{Name: "MANAGED", Value: pointer("original"), Release: true}}); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(path)
	if strings.Contains(string(body), "export MANAGED='original'") {
		t.Fatal("fixed baseline overwrote per-shell original")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("fragment not private")
		}
	}
	conflict := filepath.Join(dir, "unrelated.sh")
	writeTestFile(t, conflict, []byte("user file"))
	bad, _ := NewPOSIXProvider(conflict, nil)
	if err := bad.Apply(context.Background(), []localstate.Change{{Name: "A", Value: pointer("x")}}); err == nil {
		t.Fatal("overwrote existing user file")
	}
	content, _ := os.ReadFile(conflict)
	if string(content) != "user file" {
		t.Fatal("user content changed")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link.sh")
		if err := os.Symlink(conflict, link); err != nil {
			t.Fatal(err)
		}
		bad, _ = NewPOSIXProvider(link, nil)
		if err := bad.Apply(context.Background(), []localstate.Change{{Name: "A", Value: pointer("x")}}); err == nil {
			t.Fatal("followed symlink")
		}
	}
}
func TestRejectUnsafeFragment(t *testing.T) {
	for _, name := range []string{"bad-name", "X;touch /tmp/no", "__HARMONIA_A", "A\nB"} {
		if _, err := RenderPOSIXFragment("id", map[string]string{name: "v"}, nil); err == nil {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
	if _, err := RenderPOSIXFragment("id", map[string]string{"A": "x\x00y"}, nil); err == nil {
		t.Fatal("accepted NUL")
	}
	if _, err := RenderPOSIXFragment("id", map[string]string{"A": "x"}, []string{"A"}); err == nil {
		t.Fatal("active release collision")
	}
}
func TestWindowsPersistentOriginalAndUserIsolation(t *testing.T) {
	sid := "S-1-5-21-111-222-333-1001"
	otherSID := "S-1-5-21-111-222-333-1002"
	store := &MemoryUserStore{SID: sid, Values: map[string]RegistryValue{"MANAGED": {Value: "%SYNTHETIC_ROOT%\\bin", Expand: true}, "UNRELATED": {Value: "keep"}}}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "registry-originals.json")
	p, err := NewPersistentWindowsProvider(sid, store, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewWindowsProvider(otherSID, store); err == nil {
		t.Fatal("accepted wrong SID")
	}
	if _, err := p.Snapshot(context.Background(), []string{"MANAGED", "NEW_KEY"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "MANAGED", Value: pointer("cloud")}, {Name: "NEW_KEY", Value: pointer("new")}}); err != nil {
		t.Fatal(err)
	}
	p, err = NewPersistentWindowsProvider(sid, store, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "MANAGED", Value: pointer("ignored"), Release: true}, {Name: "NEW_KEY", Release: true}}); err != nil {
		t.Fatal(err)
	}
	original, exists, _ := store.Read("managed")
	if !exists || original.Value != "%SYNTHETIC_ROOT%\\bin" || !original.Expand {
		t.Fatal("original registry type/value not restored after restart")
	}
	if _, exists, _ := store.Read("NEW_KEY"); exists {
		t.Fatal("new key not removed")
	}
	if value, _, _ := store.Read("UNRELATED"); value.Value != "keep" {
		t.Fatal("unrelated value changed")
	}
	if err := store.Set("MANAGED", RegistryValue{Value: "independent second value"}); err != nil {
		t.Fatal(err)
	}
	p, err = NewPersistentWindowsProvider(sid, store, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(context.Background(), []string{"MANAGED"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "MANAGED", Value: pointer("cloud2")}, {Name: "MANAGED", Release: true}}); err != nil {
		t.Fatal(err)
	}
	original, _, _ = store.Read("MANAGED")
	if original.Value != "independent second value" || original.Expand {
		t.Fatal("second takeover restored stale original type")
	}
	if _, err := NewPersistentWindowsProvider(otherSID, &MemoryUserStore{SID: otherSID}, path); err == nil {
		t.Fatal("loaded other user's state")
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "path", Value: pointer("a")}, {Name: "PATH", Value: pointer("b")}}); err == nil {
		t.Fatal("accepted Windows name collision")
	}
}
func TestServicesSafeBindings(t *testing.T) {
	cfg := ServiceConfig{UserName: "harmonia-test", UserID: "1001", BinaryPath: "/usr/local/bin/harmonia", StateDirectory: "/var/lib/harmonia/1001"}
	linux, err := Systemd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"User=harmonia-test", "NoNewPrivileges=true", "ProtectHome=true", "CapabilityBoundingSet=", "--local-user", "--local-directory"} {
		if !strings.Contains(string(linux.Content), required) {
			t.Fatal("missing " + required)
		}
	}
	for _, forbidden := range []string{"--state", "--platform-fragment", "--fixture"} {
		if strings.Contains(string(linux.Content), forbidden) {
			t.Fatal("正式服务包含fixture/旧明文参数", forbidden)
		}
	}
	mac, err := LaunchDaemon(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mac.Content), "<string>--local-directory</string>") || strings.Contains(string(mac.Content), "<string>--state</string>") {
		t.Fatal("LaunchDaemon未使用加密目录")
	}
	decoder := xml.NewDecoder(strings.NewReader(string(mac.Content)))
	for {
		_, err := decoder.Token()
		if err != nil {
			if err.Error() != "EOF" {
				t.Fatal(err)
			}
			break
		}
	}
	cfg.UserID = "0"
	if _, err := LaunchDaemon(cfg); err == nil {
		t.Fatal("accepted root")
	}
	cfg.UserID = "1001"
	cfg.UserName = "x\nUser=root"
	if _, err := Systemd(cfg); err == nil {
		t.Fatal("accepted injection")
	}
	cfg.UserName = "harmonia-test"
	cfg.BinaryPath = "/root/harmonia/bin"
	if _, err := Systemd(cfg); err == nil {
		t.Fatal("accepted ProtectHome path")
	}
	win, err := WindowsService(ServiceConfig{UserID: "S-1-5-21-111-222-333-1001", BinaryPath: `C:\Program Files\Harmonia\harmonia.exe`, StateDirectory: `C:\ProgramData\Harmonia\test-user`})
	if err != nil {
		t.Fatal(err)
	}
	var manifest WindowsServiceManifest
	if err := json.Unmarshal(win.Content, &manifest); err != nil {
		t.Fatal(err)
	}
	if !serviceNamePattern.MatchString(manifest.ServiceName) || !strings.HasPrefix(manifest.Account, `NT SERVICE\`) {
		t.Fatal("unbound service account")
	}
	if len(manifest.Arguments) < 3 || manifest.Arguments[1] != "--local-directory" || len(manifest.Gates) == 0 || !strings.Contains(manifest.Gates[0], "仍关闭") {
		t.Fatal("Windows清单未绑定新接口和原生关闭门槛")
	}
	for _, argument := range manifest.Arguments {
		if argument == "--state" || argument == "--fixture" {
			t.Fatal("正式清单包含fixture/旧参数")
		}
	}
	cfg.BinaryPath = "/usr/local/bin/harmonia"
	cfg.CAFile = "/usr/local/share/harmonia-test/ca.pem"
	withCA, err := Systemd(cfg)
	if err != nil || !strings.Contains(string(withCA.Content), "--ca-file") {
		t.Fatal("显式CA未进入服务参数", err)
	}
	cfg.CAFile = "/usr/local/share/ca.pem\nUser=root"
	if _, err := Systemd(cfg); err == nil {
		t.Fatal("接受CA路径注入")
	}
	if _, err := WindowsService(ServiceConfig{UserID: "not-a-SID", BinaryPath: `C:\harmonia.exe`, StateDirectory: `C:\harmonia`}); err == nil {
		t.Fatal("accepted invalid SID")
	}
}
func TestBashHookPreservesPromptArray(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires bash")
	}
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	dir := t.TempDir()
	fragment := filepath.Join(dir, "environment.sh")
	writeTestFile(t, fragment, []byte(fragmentMarker))
	hook, err := RenderShellHook("bash", fragment)
	if err != nil {
		t.Fatal(err)
	}
	script := "set -eu\nPROMPT_COMMAND=('echo preserved' ':')\n" + hook + hook + "[[ ${#PROMPT_COMMAND[@]} == 3 ]]\n[[ ${PROMPT_COMMAND[1]} == 'echo preserved' ]]\n"
	cmd := exec.Command(shell, "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook failed: %v %s", err, output)
	}
}
