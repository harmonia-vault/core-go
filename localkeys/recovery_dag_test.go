package localkeys

import (
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/localstate"
	"testing"
)

func TestDAGJournalOwnerEpochAndLogoutTombstone(t *testing.T) {
	v := openTest(t, testConfig(t))
	epoch, err := v.RecoveryDAGOwnerEpoch("synthetic-account", 1)
	if err != nil || epoch != 0 {
		t.Fatal(err)
	}
	if err = v.SaveRecoveryDAGJournal("synthetic-account", 1, epoch, []byte(`{"synthetic":"public original"}`)); err != nil {
		t.Fatal(err)
	}
	state := localstate.EmptyState()
	state.SessionEpoch = 1
	raw, _ := json.Marshal(state)
	if err = v.Save("state-v1", raw); err != nil {
		t.Fatal(err)
	}
	if _, err = v.LoadRecoveryDAGJournal("synthetic-account", 1, epoch); !errors.Is(err, ErrIdentity) {
		t.Fatal("old RAM epoch accessed new state")
	}
	if err = v.SaveRecoveryDAGJournal("synthetic-account", 1, epoch, []byte("old")); !errors.Is(err, ErrIdentity) {
		t.Fatal("old RAM epoch rewrote journal")
	}
	state.AccountClosed = true
	raw, _ = json.Marshal(state)
	if err = v.Save("state-v1", raw); err != nil {
		t.Fatal(err)
	}
	if err = v.Delete("recovery-dag-v1"); err != nil {
		t.Fatal(err)
	}
	if err = v.SaveRecoveryDAGJournal("synthetic-account", 1, 1, []byte("after logout")); !errors.Is(err, ErrIdentity) {
		t.Fatal("logout tombstone allowed recreated journal")
	}
	if _, err = v.RecoveryDAGOwnerEpoch("synthetic-account", 1); !errors.Is(err, ErrIdentity) {
		t.Fatal("logout tombstone provided new recovery owner")
	}
}
