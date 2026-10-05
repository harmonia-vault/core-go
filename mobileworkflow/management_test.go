package mobileworkflow

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

func TestManagementProtectedHighestRejectsAbsentRollbackAndEquivocation(t *testing.T) {
	signed := cryptox.SignedGrantWire{Grant: cryptox.Grant{AccountID: "account", AccountGeneration: "1", IssuerDeviceID: "admin", SubjectDeviceID: "reader", SubjectSigningPublicKey: cryptox.EncodeBase64(make([]byte, 32)), SubjectReceivingPublicKey: cryptox.EncodeBase64(make([]byte, 32)), EnvironmentID: "env", KeyVersion: "1", GrantGeneration: "4", Role: "none", ExpiresAt: "0", IdempotencyKey: "none-four"}, Signature: cryptox.EncodeBase64(make([]byte, 64))}
	hash, e := syncclient.GrantContentHash(signed)
	if e != nil {
		t.Fatal(e)
	}
	w := &Workflow{state: protectedState{Management: &managementState{History: map[string]ManagementResult{}, Highest: map[string]map[string]managementBound{"env": {"reader": {Generation: 4, Fingerprint: hash}}}}}}
	control := syncclient.ManagementControl{EnvironmentID: "env", Subjects: []syncclient.ManagementSubject{{DeviceID: "reader", CurrentGrant: &signed, HighestGrantGeneration: "4"}}}
	if e = w.checkManagementBounds(control); e != nil {
		t.Fatal("exact highest checkpoint rejected", e)
	}
	control.Subjects[0].CurrentGrant = nil
	control.Subjects[0].HighestGrantGeneration = "0"
	if !errors.Is(w.checkManagementBounds(control), ErrManagementConflict) {
		t.Fatal("server absence reset protected highest generation")
	}
	control.Subjects[0].CurrentGrant = &signed
	control.Subjects[0].HighestGrantGeneration = "3"
	if !errors.Is(w.checkManagementBounds(control), ErrManagementConflict) {
		t.Fatal("server generation rollback accepted")
	}
	control.Subjects[0].HighestGrantGeneration = "4"
	signed.Grant.IdempotencyKey = "different-four"
	if !errors.Is(w.checkManagementBounds(control), ErrManagementConflict) {
		t.Fatal("same generation different signed packet accepted")
	}
}
func TestManagementUntrustedClosedAndOtherPendingGates(t *testing.T) {
	c := testConfig(t)
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	in := syncclient.GrantUpdateIntent{ID: "selected", EnvironmentID: "env", SubjectDeviceID: "reader", Role: "rw"}
	if _, e = w.PrepareDeviceGrant(context.Background(), in); !errors.Is(e, ErrNotTrusted) {
		t.Fatal("untrusted workflow prepared managed grant", e)
	}
	if _, e = w.PrepareOtherDeviceRevocation(context.Background(), "revoke", "reader", "env"); !errors.Is(e, ErrNotTrusted) {
		t.Fatal("untrusted workflow prepared global revocation", e)
	}
	w.state.Management = &managementState{Pending: &managementRecord{ID: "pending", Attempted: true}, History: map[string]ManagementResult{}, Highest: map[string]map[string]managementBound{}}
	if !errors.Is(w.CancelManagement("pending"), ErrManagementPending) {
		t.Fatal("attempted unknown transaction cancellable")
	}
	if _, e = w.View(); !errors.Is(e, ErrManagementPending) {
		t.Fatal("management pending did not gate cache view", e)
	}
	w.state.RecoveryDAG = &recoveryDAGState{}
	if _, e = w.RetryManagement(context.Background(), "pending"); !errors.Is(e, ErrRecoveryRestricted) {
		t.Fatal("recovery proof reused as device manager", e)
	}
	w.Close()
	if _, e = w.ManagementInfo(); !errors.Is(e, ErrClosed) {
		t.Fatal("closed device returned management metadata", e)
	}
}

func TestManagementHistoryLimitRefusesWithoutDroppingRetiredIDs(t *testing.T) {
	w := &Workflow{state: protectedState{Management: &managementState{History: map[string]ManagementResult{}, Highest: map[string]map[string]managementBound{}}}}
	for i := 0; i < 256; i++ {
		id := "retired-" + strconv.Itoa(i)
		w.state.Management.History[id] = ManagementResult{ID: id, Canceled: true}
	}
	if !errors.Is(w.managementUnusedID("new-operation"), ErrManagementLimit) || len(w.state.Management.History) != 256 {
		t.Fatal("bounded history discarded cancellation identity")
	}
	if !errors.Is(w.managementUnusedID("retired-0"), ErrManagementConflict) {
		t.Fatal("old retired id reused after limit")
	}
}

func TestManagementLateTrustInvalidationClearsProtectedPending(t *testing.T) {
	c := testConfig(t)
	var saved protectedState
	c.SaveProtectedState = func(data []byte) error { return decode(data, &saved) }
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	packet := []byte("synthetic-short-session-and-signed-packet")
	w.state.Management = &managementState{Pending: &managementRecord{ID: "late-invalidation", Packet: packet, Attempted: true}, History: map[string]ManagementResult{}, Highest: map[string]map[string]managementBound{}}
	if e = w.engine.Logout(); e != nil {
		t.Fatal(e)
	}
	if e = w.managementFault(syncclient.ErrTrustInvalidated); !errors.Is(e, syncclient.ErrTrustInvalidated) || !w.closed || saved.Management != nil || saved.Root != nil || !saved.Cloud.AccountClosed {
		t.Fatal("late network invalidation retained protected management or trust", e)
	}
	for _, value := range packet {
		if value != 0 {
			t.Fatal("late invalidation retained original bearer packet in memory")
		}
	}
}
