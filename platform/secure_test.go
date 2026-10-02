package platform

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
)

func protectedVault(t *testing.T) (*localkeys.Vault, localkeys.Config) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid, err := localkeys.CurrentUserID()
	if err != nil {
		t.Fatal(err)
	}
	c := localkeys.Config{Directory: filepath.Join(root, "protected"), UserID: uid}
	v, err := localkeys.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, c
}
func TestSecurePOSIXEncryptedMetadataRestartPauseAndRestoration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("实际 POSIX shell 需要 POSIX")
	}
	v, c := protectedVault(t)
	fragment := filepath.Join(c.Directory, "environment.sh")
	p, err := NewSecurePOSIXProvider(fragment, v)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic-cloud-secret")}, {Name: "NEW_KEY", Value: pointer("synthetic-added")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fragment + ".state.json"); !os.IsNotExist(err) {
		t.Fatal("secure provider created plaintext metadata")
	}
	data, err := os.ReadFile(filepath.Join(c.Directory, "provider.v1.enc"))
	if err != nil || bytes.Contains(data, []byte("synthetic-cloud-secret")) {
		t.Fatal("provider metadata is not encrypted")
	}
	copies := filepath.Dir(c.Directory)
	copyFragment := func(name string) string {
		data, err := os.ReadFile(fragment)
		if err != nil {
			t.Fatal(err)
		}
		name = filepath.Join(copies, name)
		writeTestFile(t, name, data)
		quoted, _ := ShellQuote(name)
		return quoted
	}
	active := copyFragment("active.sh")
	if err := p.SetPaused(ctx, true); err != nil {
		t.Fatal(err)
	}
	paused := copyFragment("paused.sh")
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	v, err = localkeys.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	p, err = NewSecurePOSIXProvider(fragment, v)
	if err != nil || !p.state.Paused || p.state.Revisions["TOKEN"] != 1 {
		t.Fatal("encrypted pause/revision not restored")
	}
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic-fallback")}}); err != nil {
		t.Fatal(err)
	}
	fallback := copyFragment("fallback.sh")
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Release: true}, {Name: "NEW_KEY", Release: true}}); err != nil {
		t.Fatal(err)
	}
	released := copyFragment("released.sh")
	script := "set -eu\nexport TOKEN='original' UNRELATED='keep'\nunset NEW_KEY\n. " + active + "\n[ \"$TOKEN\" = synthetic-cloud-secret ]\n. " + paused + "\nTOKEN=external-paused\n. " + paused + "\n[ \"$TOKEN\" = external-paused ]\n. " + fallback + "\n[ \"$TOKEN\" = synthetic-fallback ]\nTOKEN=external-after-fallback\n. " + fallback + "\n[ \"$TOKEN\" = external-after-fallback ]\n. " + released + "\n[ \"$TOKEN\" = original ]\n[ \"${NEW_KEY+x}\" != x ]\n[ \"$UNRELATED\" = keep ]\nTOKEN=after-release\n. " + released + "\n[ \"$TOKEN\" = after-release ]\n"
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual shell failed: %v %s", err, output)
	}
}
func TestSecureProviderRejectsFixtureWrongPathCorruptionAndNonOwnedFragment(t *testing.T) {
	v, c := protectedVault(t)
	fragment := filepath.Join(c.Directory, "environment.sh")
	if _, err := NewSecurePOSIXProvider(filepath.Join(c.Directory, "other.sh"), v); err == nil {
		t.Fatal("unbound fragment path accepted")
	}
	writeTestFile(t, fragment+".state.json", []byte(`{"synthetic":true}`))
	if _, err := NewSecurePOSIXProvider(fragment, v); err == nil {
		t.Fatal("plaintext fixture migrated")
	}
	if err := os.Remove(fragment + ".state.json"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, fragment, []byte("# independent user file\n"))
	p, err := NewSecurePOSIXProvider(fragment, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(context.Background(), []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic")}}); err == nil {
		t.Fatal("non-tool fragment replaced")
	}
	data, _ := os.ReadFile(fragment)
	if string(data) != "# independent user file\n" {
		t.Fatal("unrelated file changed")
	}
	if err := os.Remove(fragment); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Directory, "provider.v1.enc")
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	writeTestFile(t, path, data)
	if _, err := NewSecurePOSIXProvider(fragment, v); err == nil {
		t.Fatal("corrupt encrypted metadata accepted")
	}
}
func TestSecureWindowsFakeOriginalTypesRestartAndRetakeover(t *testing.T) {
	v, c := protectedVault(t)
	sid := "S-1-5-21-100-200-300-1001"
	if runtime.GOOS == "windows" {
		sid = c.UserID
	}
	fake := &MemoryUserStore{SID: sid, Values: map[string]RegistryValue{"TOKEN": {Value: "%SYNTHETIC_ORIGINAL%", Expand: true}, "UNRELATED": {Value: "keep"}}}
	p, err := NewSecureWindowsProvider(sid, fake, v)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic-cloud")}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(c.Directory, "windows-originals.v1.enc"))
	if err != nil || bytes.Contains(data, []byte("SYNTHETIC_ORIGINAL")) {
		t.Fatal("Windows original is not encrypted")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	v, err = localkeys.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	p, err = NewSecureWindowsProvider(sid, fake, v)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Release: true}}); err != nil {
		t.Fatal(err)
	}
	if fake.Values["TOKEN"] != (RegistryValue{Value: "%SYNTHETIC_ORIGINAL%", Expand: true}) {
		t.Fatal("type/original lost after restart")
	}
	fake.Values["TOKEN"] = RegistryValue{Value: "fresh-local-original"}
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Value: pointer("synthetic-cloud")}, {Name: "NEW_KEY", Value: pointer("synthetic-added")}}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(ctx, []localstate.Change{{Name: "TOKEN", Release: true}, {Name: "NEW_KEY", Release: true}}); err != nil {
		t.Fatal(err)
	}
	if fake.Values["TOKEN"] != (RegistryValue{Value: "fresh-local-original"}) || fake.Values["UNRELATED"].Value != "keep" {
		t.Fatal("retakeover used stale original or changed unrelated")
	}
	if _, ok := fake.Values["NEW_KEY"]; ok {
		t.Fatal("tool-added key not removed")
	}
}
