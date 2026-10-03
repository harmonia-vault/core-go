//go:build darwin

package macosservice

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const journalCrashBody = "{\"syntheticFilesystemOnly\":true}\n"

// 仅普通测试用户自己的临时 FD；不调用 Manager.New、sudo、launchctl 或安装路径。
func TestDarwinJournalCrashChild(t *testing.T) {
	dir := os.Getenv("HARMONIA_SYNTHETIC_JOURNAL_DIR")
	if dir == "" {
		return
	}
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		os.Exit(85)
	}
	defer unix.Close(fd)
	var old *node
	if n, e := inspectAt(fd, "journal.json"); e == nil {
		old = &n
	}
	step := os.Getenv("HARMONIA_SYNTHETIC_JOURNAL_STEP")
	_, e = publishAtSteps(fd, "journal.json", old, []byte(journalCrashBody), uint32(os.Getuid()), uint32(os.Getgid()), func(name string) {
		if name == step {
			os.Exit(86)
		}
	})
	if e != nil {
		os.Exit(84)
	}
	os.Exit(83)
}
func TestDarwinJournalRealProcessCrashLeavesOnlySingleLinkUnreferencedStage(t *testing.T) {
	for _, replace := range []bool{false, true} {
		for _, step := range []string{"created", "written", "file-synced", "renamed", "directory-synced"} {
			t.Run(step+"-"+map[bool]string{false: "new", true: "replace"}[replace], func(t *testing.T) {
				dir := t.TempDir()
				fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if e != nil {
					t.Fatal(e)
				}
				defer unix.Close(fd)
				if replace {
					if _, e = publishAt(fd, "journal.json", nil, []byte("{\"syntheticOld\":true}\n"), uint32(os.Getuid()), uint32(os.Getgid())); e != nil {
						t.Fatal(e)
					}
				}
				exe, e := os.Executable()
				if e != nil {
					t.Fatal(e)
				}
				child := exec.Command(exe, "-test.run=^TestDarwinJournalCrashChild$")
				child.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HARMONIA_SYNTHETIC_JOURNAL_DIR=" + dir, "HARMONIA_SYNTHETIC_JOURNAL_STEP=" + step}
				e = child.Run()
				exit, ok := e.(*exec.ExitError)
				if !ok || exit.ExitCode() != 86 {
					t.Fatal("没有在指定写入边界真正退出", e)
				}
				stages := map[string][]byte{}
				entries, e := os.ReadDir(dir)
				if e != nil {
					t.Fatal(e)
				}
				for _, entry := range entries {
					n, e := inspectAt(fd, entry.Name())
					if e != nil || n.Kind != regular || n.Links != 1 || n.Mode != 0600 {
						t.Fatal("原子写入产生了未知类型/双硬链接", n, e)
					}
					if strings.HasPrefix(entry.Name(), ".journal.json.stage.") {
						b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
						if e != nil {
							t.Fatal(e)
						}
						stages[entry.Name()] = b
					}
				}
				if step == "created" && (len(stages) != 1 || len(firstStage(stages)) != 0) {
					t.Fatal("没有覆盖write前空stage真实崩溃")
				}
				var old *node
				if n, e := inspectAt(fd, "journal.json"); e == nil {
					old = &n
				}
				if _, e = publishAt(fd, "journal.json", old, []byte(journalCrashBody), uint32(os.Getuid()), uint32(os.Getgid())); e != nil {
					t.Fatal("随机未引用stage阻塞了新尝试", e)
				}
				b, e := os.ReadFile(filepath.Join(dir, "journal.json"))
				if e != nil || string(b) != journalCrashBody {
					t.Fatal("权威文件不是完整新记录", e)
				}
				for name, before := range stages {
					after, e := os.ReadFile(filepath.Join(dir, name))
					if e != nil || !bytes.Equal(before, after) {
						t.Fatal("猜删或覆盖了崩溃残留stage")
					}
				}
			})
		}
	}
}
func firstStage(values map[string][]byte) []byte {
	for _, value := range values {
		return value
	}
	return nil
}

func TestDarwinJournalCompareByFDRefusesReplacedAuthoritativeInode(t *testing.T) {
	dir := t.TempDir()
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	n, e := publishAt(fd, "journal.json", nil, []byte(journalCrashBody), uint32(os.Getuid()), uint32(os.Getgid()))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(dir, "journal.json"), filepath.Join(dir, "retained-original")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "journal.json"), []byte("unknown-root-object"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = publishAt(fd, "journal.json", &n, []byte(journalCrashBody), uint32(os.Getuid()), uint32(os.Getgid())); e == nil {
		t.Fatal("替换inode仍被覆盖")
	}
	b, e := os.ReadFile(filepath.Join(dir, "journal.json"))
	if e != nil || string(b) != "unknown-root-object" {
		t.Fatal("未知对象被删除/覆盖")
	}
}
