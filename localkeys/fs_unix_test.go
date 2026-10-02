//go:build darwin || linux

package localkeys

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUnixPrivatePermissionsSymlinkAndHardlinkRejection(t *testing.T) {
	c := testConfig(t)
	if err := os.Mkdir(c.Directory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.Directory, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(c); !errors.Is(err, ErrPermission) {
		t.Fatalf("wide directory accepted: %v", err)
	}
	if err := os.Chmod(c.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	v := openTest(t, c)
	if err := v.Save("state-v1", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(c.Directory, keyFile)
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatal("loaded key ignored later unsafe permissions")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.Directory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatal("loaded key ignored later unsafe directory")
	}
	if err := os.Chmod(c.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(c.Directory, "hardlink")
	if err := os.Link(key, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatal("hardlinked machine key accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(c.Directory, slots["state-v1"])
	if err := os.Link(state, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatal("hardlinked state accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(c.Directory, "unrelated")
	if err := os.WriteFile(unrelated, []byte("unrelated synthetic data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unrelated, state); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatal("followed state symlink")
	}
	if err := v.Save("state-v1", []byte("new")); !errors.Is(err, ErrPermission) {
		t.Fatal("replaced state symlink")
	}
	data, _ := os.ReadFile(unrelated)
	if string(data) != "unrelated synthetic data" {
		t.Fatal("unrelated target changed")
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, original, 0600); err != nil {
		t.Fatal(err)
	}
	v.Close()
	link := filepath.Join(filepath.Dir(c.Directory), "linked-directory")
	if err := os.Symlink(c.Directory, link); err != nil {
		t.Fatal(err)
	}
	c.Directory = link
	if _, err := Open(c); !errors.Is(err, ErrPermission) {
		t.Fatal("followed directory symlink")
	}
}
func TestMachineKeyChangeWhileOpenFailsClosed(t *testing.T) {
	c := testConfig(t)
	v := openTest(t, c)
	path := filepath.Join(c.Directory, keyFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err := v.Save("state-v1", []byte("synthetic")); !errors.Is(err, ErrCorrupt) {
		t.Fatal("machine key record changed while open")
	}
}
func TestNativeExtendedACLIsRejected(t *testing.T) {
	c := testConfig(t)
	v := openTest(t, c)
	path := filepath.Join(c.Directory, keyFile)
	var command *exec.Cmd
	if runtime.GOOS == "darwin" {
		command = exec.Command("/bin/chmod", "+a", "everyone allow read", path)
		defer exec.Command("/bin/chmod", "-N", path).Run()
	} else {
		binary, err := exec.LookPath("setfacl")
		if err != nil {
			t.Skip("setfacl unavailable; native ACL negative test not run")
		}
		command = exec.Command(binary, "-m", "u:65534:r,m::---", path)
	}
	command.Env = []string{"PATH=/usr/bin:/bin"}
	if err := command.Run(); err != nil {
		t.Fatalf("cannot set isolated synthetic ACL: %v", err)
	}
	if _, err := v.Load("state-v1"); !errors.Is(err, ErrPermission) {
		t.Fatalf("extended ACL not rejected: %v", err)
	}
}
