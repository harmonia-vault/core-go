package syncclient

import (
	"context"
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"net/http"
	"net/http/httptest"
	"testing"
)

func (f *cryptoFixture) deleteEnvironment(t *testing.T, sequence uint64) EnvironmentEvent {
	t.Helper()
	g := f.grant.Grant
	g.Role = "admin"
	authority := f.resignGrant(t, g)
	change := cryptox.EnvironmentChange{AccountID: "acct", AccountGeneration: "1", DeviceID: "dev", EnvironmentID: "env", Operation: "delete", AuthorityEnvironmentID: "env", AuthorityKeyVersion: "1", AuthorityGrantGeneration: "1", PreviousKeyVersion: "1", KeyVersion: "1", ExpectedSequence: fmtInt(int64(sequence - 1)), IdempotencyKey: "delete-env", RecoveryGeneration: "1", Grants: []cryptox.SignedGrantWire{}, Mutations: []cryptox.SignedMutationWire{}}
	signed, err := cryptox.SignEnvironmentChange(change, f.devicePrivate)
	check(t, err)
	return EnvironmentEvent{Sequence: sequence, Change: signed, Authorization: authority, Subjects: []string{"dev"}}
}
func TestPauseAuthorizationCheckpointPreservesDataAndResumeFullCatchup(t *testing.T) {
	f := newCryptoFixture(t)
	engine := testEngine(t)
	first := f.event(t, 1, "before-pause")
	second := f.event(t, 2, "while-paused")
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(1, first), localstate.CloudSnapshot{})
	check(t, err)
	check(t, engine.AcceptSnapshot(previous, fixedNow))
	check(t, engine.SetPaused(true))
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Harmonia-Protocol-Major", "2")

		w.Header().Set("Harmonia-Protocol-Major", "2")
		requests = append(requests, r.URL.RawQuery)
		pull := f.pull(2)
		if r.URL.Query().Get("scope") == "authorizations" {
			pull.Scope = "authorizations"
		} else {
			if r.URL.Query().Get("after") != "0" {
				t.Error("resume missed full durable catchup")
			}
			pull.Events = []Event{first, second}
		}
		_ = json.NewEncoder(w).Encode(pull)
	}))
	defer server.Close()
	client := testClient(t, server, engine, f.verifier)
	_, err = client.RefreshAuthorizations(context.Background())
	check(t, err)
	state := engine.State()
	if state.Cloud.Sequence != 1 || state.Cloud.AuthorizationSequence != 2 || state.Cloud.Environments["env"].Values["TOKEN"] != "before-pause" {
		t.Fatal("projection applied ordinary data", state.Cloud)
	}
	if _, err = client.Pull(context.Background()); err != ErrPaused {
		t.Fatal(err)
	}
	check(t, engine.SetPaused(false))
	_, err = client.Pull(context.Background())
	check(t, err)
	if len(requests) != 2 || engine.State().Cloud.Environments["env"].Values["TOKEN"] != "while-paused" || engine.State().Cloud.Sequence != 2 {
		t.Fatal("resume did not rebuild", requests)
	}
}
func TestAuthorizationProjectionRejectsDataAndCannotGrantNewSources(t *testing.T) {
	f := newCryptoFixture(t)
	initial, err := f.verifier.VerifyPull(context.Background(), f.pull(1, f.event(t, 1, "cached")), localstate.CloudSnapshot{})
	check(t, err)
	pull := f.pull(2, f.event(t, 2, "forbidden-during-pause"))
	pull.Scope = "authorizations"
	if _, err = f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, initial); err == nil {
		t.Fatal("ordinary data accepted by projection")
	}
	pull.Events = nil
	pull.Scope = ""
	if _, err = f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, initial); err == nil {
		t.Fatal("unmarked ordinary response accepted")
	}
	pull.Scope = "authorizations"
	empty := localstate.CloudSnapshot{IssuerEvidence: initial.IssuerEvidence, AccountID: "acct", AccountGeneration: 1, Sequence: 1, Environments: map[string]localstate.Environment{}}
	out, err := f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, empty)
	check(t, err)
	if len(out.Environments) != 0 || out.Sequence != 1 || out.AuthorizationSequence != 2 {
		t.Fatal("new source appeared while paused", out)
	}
}
func TestSignedDeletionDuringPauseDropsCacheOverridesAndReplaysFailClosed(t *testing.T) {
	f := newCryptoFixture(t)
	engine := testEngine(t)
	previous, err := f.verifier.VerifyPull(context.Background(), f.pull(1, f.event(t, 1, "old-cache")), localstate.CloudSnapshot{})
	check(t, err)
	check(t, engine.AcceptSnapshot(previous, fixedNow))
	check(t, engine.Activate("env", 1, fixedNow))
	check(t, engine.SetOverride("env", "TOKEN", "private-override", fixedNow))
	check(t, engine.SetPaused(true))
	pull := Pull{Scope: "authorizations", AccountID: "acct", AccountGeneration: "1", Sequence: 2, Grants: []SignedGrant{}, Events: []Event{}, EnvironmentEvents: []EnvironmentEvent{f.deleteEnvironment(t, 2)}}
	out, err := f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, previous)
	check(t, err)
	check(t, engine.AcceptAuthorizationRefreshAtEpoch(out, fixedNow, engine.State().SessionEpoch))
	if len(engine.State().Cloud.Environments) != 0 || len(engine.State().Overrides) != 0 || out.DeletedEnvironments["env"] != 2 || out.Sequence != 1 {
		t.Fatal("deletion did not remove cached authority")
	}
	revival := f.pull(3)
	if _, err = f.verifier.VerifyPull(context.Background(), revival, out); err == nil {
		t.Fatal("deleted ID revived by old signed grant")
	}
	pull.Sequence = 3
	pull.EnvironmentEvents[0].Sequence = 3
	if _, err = f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, out); err == nil {
		t.Fatal("delete signature was assigned a new sequence")
	}
}
func TestEnvironmentDeleteRequiresSignedAdminAndExactBinding(t *testing.T) {
	for _, kind := range []string{"role", "signature", "account", "authority-version", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			f := newCryptoFixture(t)
			event := f.deleteEnvironment(t, 2)
			switch kind {
			case "role":
				event.Authorization = f.grant
			case "signature":
				event.Change.Signature = cryptox.EncodeBase64(make([]byte, 64))
			case "account":
				event.Change.Change.AccountID = "other"
			case "authority-version":
				event.Change.Change.AuthorityKeyVersion = "2"
			case "duplicate":
			}
			pull := Pull{Scope: "authorizations", AccountID: "acct", AccountGeneration: "1", Sequence: 2, EnvironmentEvents: []EnvironmentEvent{event}}
			if kind == "duplicate" {
				pull.EnvironmentEvents = append(pull.EnvironmentEvents, event)
			}
			if _, err := f.verifier.VerifyAuthorizationRefresh(context.Background(), pull, localstate.CloudSnapshot{}); err == nil {
				t.Fatal("invalid lifecycle proof accepted")
			}
		})
	}
}
