//go:build linux

package linuxinstall

import (
	"context"
	"testing"
)

// Linux root temp filesystem with injected system-manager/helper responses.
// Compilation on Darwin is not native execution or a real systemd/online test.
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
