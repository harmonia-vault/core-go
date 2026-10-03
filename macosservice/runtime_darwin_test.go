//go:build darwin

package macosservice

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestLaunchStateRejectsDifferentServiceAndCA(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	l := paths(target)
	text := "system/" + l.Label + " = {\npath = " + l.Plist + "\ntype = LaunchDaemon\nprogram = " + l.Binary + "\nusername = synthetic\narguments = {\n" + strings.Join([]string{l.Binary, "daemon", "--local-directory", l.State, "--local-user", "501", "--interval", "2s"}, "\n") + "\n}\n}"
	if launchState([]byte(text), 0, l, target) != matching {
		t.Fatal("准确服务未匹配")
	}
	for _, bad := range []string{strings.Replace(text, l.Binary, "/tmp/unknown", 1), strings.Replace(text, "username = synthetic", "username = root", 1), strings.Replace(text, "type = LaunchDaemon", "type = LaunchAgent", 1), strings.Replace(text, "--local-user\n501", "--local-user\n502", 1)} {
		if launchState([]byte(bad), 0, l, target) != unknown {
			t.Fatal("误接受其他服务")
		}
	}
	l.CAEnabled = true
	if launchState([]byte(text), 0, l, target) != unknown {
		t.Fatal("遗漏指定 CA 仍匹配")
	}
	withCA := strings.Replace(text, "\n}\n}", "\n--ca-file\n"+l.CA+"\n}\n}", 1)
	if launchState([]byte(withCA), 0, l, target) != matching {
		t.Fatal("指定 CA 未匹配")
	}
	if launchState([]byte(`Could not find service "`+l.Label+`" in domain for system`), 113, l, target) != absent {
		t.Fatal("明确不存在没有区分")
	}
	if launchState([]byte("permission denied"), 1, l, target) != unknown {
		t.Fatal("未知错误当不存在")
	}
}
func TestDarwinACLMetadataOnOnlySyntheticTempFile(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "synthetic")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		t.Fatal(e)
	}
	n, e := statFD(int(f.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	if n.Kind != regular || n.UID != uint32(os.Getuid()) || n.Mode != 0600 || n.Links != 1 || n.ACL {
		t.Fatal(n)
	}
}
func TestNonRootConstructorRefusesBeforeSystemActions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("此负例需要普通用户")
	}
	if _, e := New(Target{UserName: "synthetic", UID: 501, GID: 20}); e == nil {
		t.Fatal("允许普通用户安装")
	}
}

func knownJobWithPID(target Target, pid string) string {
	l := paths(target)
	return "system/" + l.Label + " = {\npath = " + l.Plist + "\ntype = LaunchDaemon\nprogram = " + l.Binary + "\nusername = " + target.UserName + "\npid = " + pid + "\narguments = {\n" + strings.Join([]string{l.Binary, "daemon", "--local-directory", l.State, "--local-user", strconv.FormatUint(uint64(target.UID), 10), "--interval", "2s"}, "\n") + "\n}\n}"
}
func TestJobPIDRequiresOnePositivePIDAndExactKnownJob(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	good := knownJobWithPID(target, "431")
	if pid, e := jobPID([]byte(good), paths(target), target); e != nil || pid != 431 {
		t.Fatal(pid, e)
	}
	for _, bad := range []string{
		strings.Replace(good, "pid = 431\n", "", 1),
		strings.Replace(good, "pid = 431", "pid = 0", 1),
		strings.Replace(good, "pid = 431", "pid = 1", 1),
		strings.Replace(good, "pid = 431", "pid = 0431", 1),
		strings.Replace(good, "pid = 431", "pid = 431\npid = 432", 1),
		strings.Replace(good, "username = synthetic", "username = root", 1),
	} {
		if _, e := jobPID([]byte(bad), paths(target), target); !errors.Is(e, ErrUnknown) {
			t.Fatal("不明或启动中PID被采纳", e)
		}
	}
}
func TestPSPresenceParserDoesNotMistakeErrorsOrReusedPIDForExit(t *testing.T) {
	if alive, e := psExists(nil, 1, 431); e != nil || alive {
		t.Fatal(alive, e)
	}
	// 重用同一PID仍为存活，宁可等待超时；不查argv/环境，也不发送信号。
	if alive, e := psExists([]byte("  431\n"), 0, 431); e != nil || !alive {
		t.Fatal(alive, e)
	}
	for _, tc := range []struct {
		body string
		exit int
	}{{"permission denied", 1}, {"431", 1}, {"432", 0}, {"", 0}, {"431\n432", 0}, {"", 2}} {
		if _, e := psExists([]byte(tc.body), tc.exit, 431); !errors.Is(e, ErrUnknown) {
			t.Fatal(tc, e)
		}
	}
}
func TestDarwinOwnerLockIsNonBlockingAndHeldAfterUnlink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vault.lock")
	if e := os.WriteFile(p, nil, 0600); e != nil {
		t.Fatal(e)
	}
	parent, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(parent)
	n, e := inspectAt(parent, "vault.lock")
	if e != nil {
		t.Fatal(e)
	}
	lock, e := claimLockAt(parent, "vault.lock", n, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	closed := false
	defer func() {
		if !closed {
			lock.Close()
		}
	}()
	if h, e := claimLockAt(parent, "vault.lock", n, uint32(os.Getuid())); e == nil {
		h.Close()
		t.Fatal("第二FD抢到所有者锁")
	}
	other, e := os.OpenFile(p, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); e == nil {
		unix.Flock(int(other.Fd()), unix.LOCK_UN)
		t.Fatal("unlink后仍开FD的锁丢失")
	}
	if e = lock.Close(); e != nil {
		t.Fatal(e)
	}
	closed = true
	if e = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal("关闭后未释放锁", e)
	}
	unix.Flock(int(other.Fd()), unix.LOCK_UN)
}
func TestDarwinOwnerLockRejectsChangedMetadataAndSymlink(t *testing.T) {
	for _, which := range []string{"mode", "hardlink", "symlink", "owner", "inode"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "vault.lock")
			if e := os.WriteFile(p, nil, 0600); e != nil {
				t.Fatal(e)
			}
			parent, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(parent)
			n, e := inspectAt(parent, "vault.lock")
			if e != nil {
				t.Fatal(e)
			}
			uid := uint32(os.Getuid())
			switch which {
			case "mode":
				e = os.Chmod(p, 0644)
			case "hardlink":
				e = os.Link(p, filepath.Join(dir, "other"))
			case "symlink":
				e = os.Rename(p, filepath.Join(dir, "other"))
				if e == nil {
					e = os.Symlink("other", p)
				}
			case "owner":
				uid++
			case "inode":
				e = os.Rename(p, filepath.Join(dir, "other"))
				if e == nil {
					e = os.WriteFile(p, nil, 0600)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if h, e := claimLockAt(parent, "vault.lock", n, uid); e == nil {
				h.Close()
				t.Fatal("危险或已变锁被采纳")
			}
		})
	}
}

func TestDarwinLocalCommandsUseCopiedBinaryTargetIdentityAndNoInheritedEnvironment(t *testing.T) {
	target := Target{UserName: "synthetic", UID: 501, GID: 20}
	l := paths(target)
	args := []string{"logout", "--offline-local", "--local-directory", l.State, "--local-user", "501"}
	c := localCommand(context.Background(), l, target, args)
	if c.Path != l.Binary || c.Dir != l.State || !reflect.DeepEqual(c.Args, append([]string{l.Binary}, args...)) || !reflect.DeepEqual(c.Env, []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}) {
		t.Fatal("命令范围或环境不符合固定合同")
	}
	cred := c.SysProcAttr.Credential
	if cred == nil || cred.Uid != 501 || cred.Gid != 20 || len(cred.Groups) != 0 {
		t.Fatal("没有精确降权/清附加组")
	}
}
