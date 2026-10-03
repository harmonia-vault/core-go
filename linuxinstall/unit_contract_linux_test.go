//go:build linux

package linuxinstall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// Linux root temp filesystem with injected system-manager/helper responses.
// Compilation on Darwin is not native execution or a real systemd/online test.
func legacyFixtureReceipt(t *testing.T, p Plan) Receipt {
	t.Helper()
	unit, err := p.Unit()
	if err != nil {
		t.Fatal(err)
	}
	old := bytes.Replace(unit.Content, []byte("\nType=exec\n"), []byte("\nType=simple\n"), 1)
	r := currentReceipt(t)
	r.Plan = p
	r.Creations = creationPlan(p)
	r.UnitSHA256 = unitDigest(old)
	return r
}

func TestLinuxLegacySimpleInterruptedInstallAndStopUninstall(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "installed-disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			c, p, runtime := nativeFixture(t)
			legacy := legacyFixtureReceipt(t, p)
			if err := c.lease.CreateReceipt(legacy); err != nil {
				t.Fatal(err)
			}
			// A prior install-planned intent chooses old bytes without rewriting its digest.
			r := installFixture(t, c, p)
			if r.UnitSHA256 != legacy.UnitSHA256 {
				t.Fatal("interrupted receipt changed digest")
			}
			body, err := os.ReadFile(c.fs.path(p.UnitPath))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(body, []byte("\nType=simple\n")) || unitDigest(body) != legacy.UnitSHA256 {
				t.Fatal("interrupted unit changed profile")
			}
			if enabled {
				// Only mock manager/helper; no actual device trust or systemctl is injected.
				if _, err = c.start(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !runtime.active {
					t.Fatal("fixture start did not become active")
				}
			}
			if got, err := c.uninstall(context.Background()); err != nil || !got.Complete {
				t.Fatal("legacy stop/uninstall", err)
			}
			count := 0
			for _, op := range runtime.controls {
				if op == "stop" {
					count++
				}
			}
			if count != 1 || runtime.active {
				t.Fatal("legacy uninstall omitted exact stop")
			}
			if _, err = c.lease.LoadReceipt(); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("legacy receipt remained after mock uninstall", err)
			}
		})
	}
}

func TestLinuxHistoricalUnitStillRequiresActualExactBytes(t *testing.T) {
	c, p, _ := nativeFixture(t)
	legacy := legacyFixtureReceipt(t, p)
	if err := c.lease.CreateReceipt(legacy); err != nil {
		t.Fatal(err)
	}
	r := installFixture(t, c, p)
	if err := c.fs.verifyReceipt(r); err != nil {
		t.Fatal(err)
	}
	path := c.fs.path(p.UnitPath)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(body, []byte("ExecStart=/bin/sh\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("fixture did not preserve original inode")
	}
	if err = c.fs.verifyReceipt(r); err == nil {
		t.Fatal("same-inode modified legacy unit accepted")
	}
}

func TestLinuxStoppedLegacyPendingEnableUninstallKeepsMaterialsContract(t *testing.T) {
	c, p, runtime := nativeFixture(t)
	legacy := legacyFixtureReceipt(t, p)
	if err := c.lease.CreateReceipt(legacy); err != nil {
		t.Fatal(err)
	}
	r := installFixture(t, c, p)
	next := copyReceipt(r)
	next.EnableIntent = true
	if err := c.saveReceipt(&r, next); err != nil {
		t.Fatal(err)
	}
	if err := runtime.control(context.Background(), "enable", p); err != nil {
		t.Fatal(err)
	}
	identity, err := c.fs.observe(p, "enable-link", p.UnitName)
	if err != nil {
		t.Fatal(err)
	}
	next = copyReceipt(r)
	next.EnableIdentity = &identity
	if err = c.saveReceipt(&r, next); err != nil {
		t.Fatal(err)
	}
	if r.Phase != "installed-disabled" || runtime.active || r.UnitSHA256 != legacy.UnitSHA256 {
		t.Fatal("expected historical stopped pending enable shape")
	}
	for _, name := range []string{"vault.lock", "state.v1.enc", "device.v1.enc", "trust.v1.enc"} {
		writeUserFixture(t, c, p, name)
	}
	// Test-only helper completion; no fake claim of cryptographic enrollment/offline logout.
	runtime.logoutHook = func(p Plan) error {
		for _, name := range []string{"device.v1.enc", "trust.v1.enc"} {
			if err := os.Remove(c.fs.path(p.StateDirectory + "/" + name)); err != nil {
				return err
			}
		}
		return nil
	}
	before := runtime.unitTypeCalls
	if got, err := c.uninstall(context.Background()); err != nil || !got.Complete {
		t.Fatal("stopped pending-enable uninstall", err)
	}
	if runtime.logoutCalls != 1 || runtime.unitTypeCalls != before {
		t.Fatal("uninstall skipped helper or acquired new Type dependency")
	}
}

func TestLinuxUnsupportedExecPreservesReceiptAndAllowsUninstall(t *testing.T) {
	for _, stage := range []string{"install", "start"} {
		t.Run(stage, func(t *testing.T) {
			c, p, runtime := nativeFixture(t)
			if stage == "start" {
				installFixture(t, c, p)
			}
			// Declared mock of an old manager ignoring Type=exec; actual VM is not used.
			runtime.effectiveType = "simple"
			var err error
			if stage == "install" {
				_, err = c.install(context.Background(), p)
			} else {
				_, err = c.start(context.Background())
			}
			if err != ErrUnsupported {
				t.Fatal("unsupported exec did not fail closed", err)
			}
			r, err := c.lease.LoadReceipt()
			if err != nil {
				t.Fatal("receipt lost on rejection", err)
			}
			current, _ := p.Unit()
			if r.UnitSHA256 != unitDigest(current.Content) || r.EnableIntent {
				t.Fatal("rejection silently downgraded template or enabled unit")
			}
			calls := runtime.unitTypeCalls
			if got, err := c.uninstall(context.Background()); err != nil || !got.Complete {
				t.Fatal("unsupported installation could not be safely removed", err)
			}
			if runtime.unitTypeCalls != calls {
				t.Fatal("uninstall depended on exec support")
			}
		})
	}
}

func TestLinuxEnableReloadCannotChangeReadinessBeforeStart(t *testing.T) {
	c, p, runtime := nativeFixture(t)
	r := installFixture(t, c, p)
	// A declared manager mock reloads to a different Type during enable.
	// This does not claim to reproduce any existing VM failure.
	runtime.enableType = "simple"
	if _, err := c.start(context.Background()); err != ErrUnsupported {
		t.Fatal("enable reload changed readiness without rejection", err)
	}
	current, err := c.lease.LoadReceipt()
	if err != nil || current.UnitSHA256 != r.UnitSHA256 || current.Phase != "installed-disabled" || !current.EnableIntent || current.EnableIdentity == nil {
		t.Fatal("rejected reload lost immutable recovery receipt", err)
	}
	for _, operation := range runtime.controls {
		if operation == "start" {
			t.Fatal("start ran after mismatched reload")
		}
	}
	if runtime.active {
		t.Fatal("mismatched reload was started")
	}
	calls := runtime.unitTypeCalls
	if got, err := c.uninstall(context.Background()); err != nil || !got.Complete {
		t.Fatal("rejected reload could not be safely removed", err)
	}
	if runtime.unitTypeCalls != calls {
		t.Fatal("uninstall gained a readiness capability dependency")
	}
}
