package windowsaccount

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestStartReceiptRequiresExactStoppedContinuation(t *testing.T) {
	base := Receipt{Stage: "installed-disabled", ServiceCreated: true}
	for _, tc := range []struct {
		name       string
		pending    string
		state      uint32
		startType  uint32
		lastStage  string
		wantResume bool
		wantAllow  bool
	}{
		{"new-disabled", "", 1, 4, "", false, true},
		{"old-v4-manual-pending", "start-service", 1, 3, "", true, true},
		{"recorded-start-failure", "start-service", 1, 3, "start-service", true, true},
		{"recorded-wait-failure", "start-service", 1, 3, "wait-running", true, true},
		{"running-never-starts-again", "start-service", 4, 3, "start-service", false, false},
		{"unknown-state", "start-service", 0, 3, "", false, false},
		{"new-manual-not-accepted", "", 1, 3, "", false, false},
		{"pending-but-disabled", "start-service", 1, 4, "", false, false},
		{"automatic-not-accepted", "start-service", 1, 2, "", false, false},
		{"other-pending", "enable-automatic", 1, 3, "", false, false},
		{"unrecognized-operation", "start-service", 1, 3, "unrecognized", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Pending = tc.pending
			if tc.lastStage != "" {
				r.LastStart = &StartResult{Stage: tc.lastStage}
			}
			resume, allowed := mayStartReceipt(r, tc.state, tc.startType)
			if resume != tc.wantResume || allowed != tc.wantAllow {
				t.Fatalf("resume/allowed=%v/%v", resume, allowed)
			}
		})
	}
	for _, r := range []Receipt{{Stage: "files-ready", ServiceCreated: true}, {Stage: "installed-disabled"}} {
		if _, allowed := mayStartReceipt(r, 1, 4); allowed {
			t.Fatal("uninstalled/unconfirmed service accepted")
		}
	}
}

func TestStartResultKeepsNumericCodeWithoutErrorText(t *testing.T) {
	for _, tc := range []struct {
		err       error
		known, ok bool
		code      uint32
	}{
		{nil, true, true, 0},
		{syscall.Errno(1069), true, false, 1069},
		{errors.Join(errors.New("private detail"), syscall.Errno(1053)), true, false, 1053},
		{errors.New("private detail"), false, false, 0},
	} {
		r := startResult("start-service", tc.err)
		if r.CodeKnown != tc.known || r.Succeeded != tc.ok || r.Code != tc.code || r.StatusRead {
			t.Fatal("numeric result mismatch")
		}
		b, err := json.Marshal(r)
		if err != nil || strings.Contains(string(b), "private detail") {
			t.Fatal("raw error text persisted")
		}
	}
}

func TestExplicitStoppedServiceMayStartAgain(t *testing.T) {
	base := Receipt{Stage: "stopped-disabled", ServiceCreated: true, LastStart: &StartResult{Stage: "enable-automatic", Succeeded: true}}
	if resume, allowed := mayStartReceipt(base, 1, 4); resume || !allowed {
		t.Fatal("completed explicit stop could not start")
	}
	for _, state := range []uint32{0, 2, 3, 4} {
		if _, allowed := mayStartReceipt(base, state, 4); allowed {
			t.Fatal("non-stopped service accepted")
		}
	}
	for _, mode := range []uint32{0, 2, 3} {
		if _, allowed := mayStartReceipt(base, 1, mode); allowed {
			t.Fatal("non-disabled service accepted")
		}
	}
	for _, pending := range []string{"disable-and-drain", "enable-automatic", "start-service"} {
		r := base
		r.Pending = pending
		if _, allowed := mayStartReceipt(r, 1, 4); allowed {
			t.Fatal("incomplete receipt accepted")
		}
	}
	base.Pending = "start-service"
	base.LastStart = &StartResult{Stage: "wait-running"}
	if resume, allowed := mayStartReceipt(base, 1, 3); !resume || !allowed {
		t.Fatal("stopped service explicit-start continuation rejected")
	}
}
