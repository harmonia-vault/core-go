package syncclient

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

type b1BindingJournal struct{ dead bool }

func (*b1BindingJournal) Save(ProtectedDAGOperation) error { return ErrDAGRecoveryState }
func (*b1BindingJournal) Load() (ProtectedDAGOperation, error) {
	return ProtectedDAGOperation{}, os.ErrNotExist
}
func (j *b1BindingJournal) OwnerAlive() error {
	if j.dead {
		return ErrDAGRecoveryState
	}
	return nil
}
func b1VerifiedFixture(t *testing.T) (*DAGRecoverySession, *b1BindingJournal) {
	t.Helper()
	raw, err := os.ReadFile("../cryptox/testdata/recovery-dag-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Pin   cryptox.PinnedIssuerRoot  `json:"rootPin"`
		Proof cryptox.IssuerRecoveryDAG `json:"proof"`
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("public synthetic vector")
	}
	proof, err := cryptox.VerifyIssuerRecoveryDAG(f.Pin, f.Proof)
	if err != nil {
		t.Fatal(err)
	}
	point, err := proof.RecoveryCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := strconv.ParseUint(f.Pin.AccountGeneration, 10, 64)
	ed, err := cryptox.DecodeBase64(point.SigningPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	x, err := cryptox.DecodeBase64(point.ReceivingPublicKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	j := &b1BindingJournal{}
	s := &DAGRecoverySession{config: DAGRecoveryConfig{Endpoint: "https://synthetic.invalid", AccountID: f.Pin.AccountID, AccountGeneration: gen, Journal: j, Now: time.Now}, token: strings.Repeat("synthetic", 4), expires: time.Now().Unix() + 60, pin: f.Pin, proof: proof, keys: cryptox.RecoveryKeys{SigningPublic: ed, ReceivingPublic: x}, vault: DAGVault{RecoveryGeneration: point.RecoveryGeneration, RecoveryHeadHash: point.TransitionHead, RotationRequired: true, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Proof.Initialization, Records: f.Proof.Records}}}
	t.Cleanup(s.Close)
	return s, j
}
func TestDAGVerifiedBindingExactProjectionAndOpaque(t *testing.T) {
	s, _ := b1VerifiedFixture(t)
	b, err := s.VerifiedBinding()
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.vault.DependencyBundle.Initialization.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if b.Pin != s.pin || b.InitializationHash != h || b.InitializationProposalHash != s.vault.DependencyBundle.Initialization.Proof.ProposalHash || b.SessionHash != digest([]byte(s.token)) || !b.RotationRequired || b.PendingID != "" {
		t.Fatal("binding was not verified core projection")
	}
	if _, err = json.Marshal(b); err == nil {
		t.Fatal("binding serialized")
	}
	b.Pin.DeviceID = "synthetic replaced pin"
	b.RecoveryHeadHash = "other"
	again, err := s.VerifiedBinding()
	if err != nil || again.Pin != s.pin || again.RecoveryHeadHash == "other" {
		t.Fatal("public projection mutated session")
	}
}
func TestDAGVerifiedBindingRejectsInvalidLiveSource(t *testing.T) {
	for _, mode := range []string{"closed", "owner", "proof", "head", "generation", "key", "expired", "pending-not-stored"} {
		t.Run(mode, func(t *testing.T) {
			s, j := b1VerifiedFixture(t)
			switch mode {
			case "closed":
				s.Close()
			case "owner":
				j.dead = true
			case "proof":
				s.proof = nil
			case "head":
				s.vault.RecoveryHeadHash = "wrong"
			case "generation":
				s.vault.RecoveryGeneration = "999"
			case "key":
				s.keys.SigningPublic = make([]byte, 32)
			case "expired":
				s.expires = time.Now().Unix() - 1
			case "pending-not-stored":
				p := checkedOriginal(t)
				s.pending = &p
			}
			if _, err := s.VerifiedBinding(); err == nil {
				t.Fatal("invalid source projected")
			}
		})
	}
}
