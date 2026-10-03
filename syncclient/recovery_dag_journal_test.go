package syncclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
)

func TestNativeDAGJournalOriginalIdentityRestartAndMonotonicState(t *testing.T) {
	raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("synthetic public vector invalid")
	}
	submission := vector.Proof.Records[4].TransitionV2.Submission
	bundle := cryptox.RecoveryDependencyBundle{Initialization: vector.Proof.Initialization, Records: vector.Proof.Records[:4]}
	hash, err := cryptox.RecoveryTransitionHashV2(submission)
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseUint(vector.Pin.AccountGeneration, 10, 64)
	p := ProtectedDAGOperation{Version: 1, Endpoint: "https://synthetic.invalid", AccountID: vector.Pin.AccountID, AccountGeneration: gen, Pin: vector.Pin, Kind: "transition-v2", OperationID: submission.Transition.OperationID, ContentHash: hash, Transition: &cryptox.RecoveryTransitionCommandV2{Submission: submission, DependencyBundle: bundle}}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uid, err := localkeys.CurrentUserID()
	if err != nil {
		t.Fatal(err)
	}
	config := localkeys.Config{Directory: filepath.Join(parent, "owner"), UserID: uid}
	v, err := localkeys.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	j, err := NewVaultDAGJournal(v, p.Endpoint, p.AccountID, p.AccountGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Save(p); err != nil {
		t.Fatal(err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if err = j.OwnerAlive(); !errors.Is(err, localkeys.ErrClosed) {
		t.Fatal("closed native owner remained live")
	}
	v, err = localkeys.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	j, err = NewVaultDAGJournal(v, p.Endpoint, p.AccountID, p.AccountGeneration)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := j.Load()
	if err != nil || !sameJSON(loaded, p) {
		t.Fatal("restart changed sealed original packet", err)
	}
	foreign, err := NewVaultDAGJournal(v, "https://another.synthetic.invalid", p.AccountID, p.AccountGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = foreign.Load(); err == nil {
		t.Fatal("other endpoint loaded original identity")
	}
	p.Attempted = true
	if err = j.Save(p); err != nil {
		t.Fatal(err)
	}
	p.Attempted = false
	if err = j.Save(p); err == nil {
		t.Fatal("attempted state rolled back")
	}
	p.Attempted = true
	expected, _ := strconv.ParseUint(submission.Transition.ExpectedSequence, 10, 64)
	p.AcceptedSequence = expected + 1
	p.Applied = true
	if err = j.Save(p); err != nil {
		t.Fatal(err)
	}
	p.Applied = false
	if err = j.Save(p); err == nil {
		t.Fatal("final native application rolled back")
	}
}
