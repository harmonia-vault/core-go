package syncclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

const MaxDAGPreparationBytes = 2*cryptox.MaxRecoveryAuthorityBytes + 16384

var (
	ErrDAGRequestUnavailable  = errors.New("HTTPS DAG recovery request failed")
	ErrDAGPreparationPending  = errors.New("original DAG preparation remains pending")
	ErrDAGPreparationConflict = errors.New("original DAG preparation basis changed; preserve original intent")
	ErrDAGNewCodeMismatch     = errors.New("complete new recovery code does not match prepared public keys")
)

type DAGTransitionPreparationStore interface {
	LoadTransitionPreparation() (DAGTransitionPreparation, error)
	SaveTransitionPreparation(DAGTransitionPreparation) error
}

// 仅公开材料；不能当作完整原签包或认证凭据。无seed/code/bearer/private key。
type DAGTransitionPreparation struct {
	Version                       int                                  `json:"version"`
	Kind                          string                               `json:"kind"`
	AuthorizationKind             string                               `json:"authorizationKind"`
	Phase                         string                               `json:"phase"`
	Endpoint                      string                               `json:"endpoint"`
	AccountID                     string                               `json:"accountId"`
	AccountGeneration             uint64                               `json:"accountGeneration"`
	Pin                           cryptox.PinnedIssuerRoot             `json:"pin"`
	InitializationHash            string                               `json:"initializationHash"`
	InitializationProposalHash    string                               `json:"initializationProposalHash"`
	SessionHash                   string                               `json:"sessionHash"`
	OperationID                   string                               `json:"operationId"`
	ExpectedSequence              uint64                               `json:"expectedSequence"`
	OldRecoveryGeneration         string                               `json:"oldRecoveryGeneration"`
	PreviousTransitionHash        string                               `json:"previousTransitionHash"`
	OldRecoverySigningPublicKey   string                               `json:"oldRecoverySigningPublicKey"`
	OldRecoveryReceivingPublicKey string                               `json:"oldRecoveryReceivingPublicKey"`
	BaseBundle                    cryptox.RecoveryDependencyBundle     `json:"baseBundle"`
	EnvironmentManifest           []cryptox.RecoveryEnvironmentVersion `json:"environmentManifest"`
	PriorOperationID              string                               `json:"priorOperationId"`
	PriorContentHash              string                               `json:"priorContentHash"`
	PriorAcceptedSequence         uint64                               `json:"priorAcceptedSequence"`
	Challenge                     *DAGTransitionChallenge              `json:"challenge,omitempty"`
	NewRecoveryGeneration         string                               `json:"newRecoveryGeneration"`
	NewSigningPublicKey           string                               `json:"newSigningPublicKey"`
	NewReceivingPublicKey         string                               `json:"newReceivingPublicKey"`
}

func dagHex(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func DecodeDAGTransitionPreparation(raw []byte) (DAGTransitionPreparation, error) {
	var p DAGTransitionPreparation
	if len(raw) == 0 || len(raw) > MaxDAGPreparationBytes || decodePreparationJSON(raw, &p) != nil {
		return p, cryptox.ErrInvalidWire
	}
	if err := ValidateDAGTransitionPreparation(p); err != nil {
		return DAGTransitionPreparation{}, err
	}
	return p, nil
}
func decodePreparationJSON(raw []byte, p *DAGTransitionPreparation) error {
	if cryptox.ValidateStrictJSON(raw, MaxDAGPreparationBytes) != nil {
		return cryptox.ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(p) != nil {
		return cryptox.ErrInvalidWire
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return cryptox.ErrInvalidWire
	}
	if !exactPreparationObject(raw, p) {
		return cryptox.ErrInvalidWire
	}
	if p.Challenge != nil {
		var outer map[string]json.RawMessage
		_ = json.Unmarshal(raw, &outer)
		if !exactPreparationObject(outer["challenge"], p.Challenge) {
			return cryptox.ErrInvalidWire
		}
	}
	return nil
}
func exactPreparationObject(raw []byte, value any) bool {
	var fields, canonical map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	b, err := json.Marshal(value)
	if err != nil || json.Unmarshal(b, &canonical) != nil || len(fields) != len(canonical) {
		return false
	}
	for k, v := range canonical {
		got, ok := fields[k]
		if !ok {
			return false
		}
		if bytes.Equal(bytes.TrimSpace(got), []byte("null")) && !bytes.Equal(v, []byte("null")) {
			return false
		}
	}
	return true
}
func ValidateDAGTransitionPreparation(p DAGTransitionPreparation) error {
	if p.Version != 1 || p.Kind != "transition-v2" || p.AuthorizationKind != "old-recovery" || validateDAGJournalBinding(DAGJournalBinding{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration}) != nil || p.Pin.AccountID != p.AccountID || p.Pin.AccountGeneration != strconv.FormatUint(p.AccountGeneration, 10) || !enrollmentID.MatchString(p.OperationID) || !dagHex(p.SessionHash) || p.ExpectedSequence == 0 || p.ExpectedSequence >= 9007199254740991 {
		return cryptox.ErrInvalidWire
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxDAGPreparationBytes {
		return cryptox.ErrInvalidWire
	}
	graph, err := cryptox.VerifyRecoveryDependencyBundle(p.Pin, p.BaseBundle)
	if err != nil {
		return err
	}
	head, err := graph.RecoveryCheckpoint()
	if err != nil {
		return err
	}
	initial, err := p.BaseBundle.Initialization.Hash()
	if err != nil {
		return err
	}
	if initial != p.InitializationHash || p.InitializationProposalHash != p.BaseBundle.Initialization.Proof.ProposalHash || p.OldRecoveryGeneration != head.RecoveryGeneration || p.PreviousTransitionHash != head.TransitionHead || p.OldRecoverySigningPublicKey != head.SigningPublicKey || p.OldRecoveryReceivingPublicKey != head.ReceivingPublicKey || head.AcceptedSequence > p.ExpectedSequence {
		return cryptox.ErrInvalidWire
	}
	if _, err = cryptox.RecoveryManifestHash(p.EnvironmentManifest); err != nil {
		return err
	}
	if p.PriorOperationID == "" {
		if p.PriorContentHash != "" || p.PriorAcceptedSequence != 0 {
			return cryptox.ErrInvalidWire
		}
	} else if !enrollmentID.MatchString(p.PriorOperationID) || p.PriorOperationID == p.OperationID || !dagHex(p.PriorContentHash) || p.PriorAcceptedSequence == 0 || p.PriorAcceptedSequence > p.ExpectedSequence {
		return cryptox.ErrInvalidWire
	}
	switch p.Phase {
	case "intent":
		if p.Challenge != nil || p.NewRecoveryGeneration != "" || p.NewSigningPublicKey != "" || p.NewReceivingPublicKey != "" {
			return cryptox.ErrInvalidWire
		}
	case "prepared":
		c := p.Challenge
		if c == nil {
			return cryptox.ErrInvalidWire
		}
		old, err := parsePositive(p.OldRecoveryGeneration)
		if err != nil || old == ^uint64(0) || p.NewRecoveryGeneration != strconv.FormatUint(old+1, 10) {
			return cryptox.ErrInvalidWire
		}
		if _, err = cryptox.DecodeBase64(p.NewSigningPublicKey, 32, 32); err != nil {
			return err
		}
		if _, err = cryptox.DecodeBase64(p.NewReceivingPublicKey, 32, 32); err != nil {
			return err
		}
		if p.NewSigningPublicKey == p.OldRecoverySigningPublicKey || p.NewReceivingPublicKey == p.OldRecoveryReceivingPublicKey {
			return cryptox.ErrInvalidWire
		}
		if !enrollmentID.MatchString(c.ChallengeID) || c.ExpiresAt <= 0 {
			return cryptox.ErrInvalidWire
		}
		if _, err = cryptox.DecodeBase64(c.Nonce, 32, 32); err != nil {
			return err
		}
		if c.OperationID != p.OperationID || c.AccountGeneration != p.Pin.AccountGeneration || c.AuthorizationKind != p.AuthorizationKind || c.AuthorizerDeviceID != "" || c.SessionHash != p.SessionHash || c.ExpectedSequence != strconv.FormatUint(p.ExpectedSequence, 10) || c.OldRecoveryGeneration != p.OldRecoveryGeneration || c.OldRecoverySigningPublicKey != p.OldRecoverySigningPublicKey || c.OldRecoveryReceivingPublicKey != p.OldRecoveryReceivingPublicKey || c.PreviousTransitionHash != p.PreviousTransitionHash || !sameJSON(c.DependencyBundle, p.BaseBundle) || !sameJSON(c.EnvironmentManifest, p.EnvironmentManifest) || c.IssuerEvidence != nil || c.AuthoritySet == nil || len(c.AuthoritySet) != 0 {
			return cryptox.ErrInvalidWire
		}
	default:
		return cryptox.ErrInvalidWire
	}
	return nil
}
func DAGPreparationSameIntent(a, b DAGTransitionPreparation) bool {
	a.Phase, b.Phase = "intent", "intent"
	a.Challenge, b.Challenge = nil, nil
	a.NewRecoveryGeneration, b.NewRecoveryGeneration = "", ""
	a.NewSigningPublicKey, b.NewSigningPublicKey = "", ""
	a.NewReceivingPublicKey, b.NewReceivingPublicKey = "", ""
	return sameJSON(a, b)
}
func ValidateDAGPreparationPromotion(p DAGTransitionPreparation, next ProtectedDAGOperation) error {
	if ValidateDAGTransitionPreparation(p) != nil || p.Phase != "prepared" || validateProtectedDAGOperation(next) != nil || next.Transition == nil || next.Kind != "transition-v2" || next.Attempted || next.AcceptedSequence != 0 || next.Applied || next.Endpoint != p.Endpoint || next.AccountID != p.AccountID || next.AccountGeneration != p.AccountGeneration || next.Pin != p.Pin || next.OperationID != p.OperationID {
		return cryptox.ErrInvalidWire
	}
	sub := next.Transition.Submission
	t := sub.Transition
	c := p.Challenge
	if t.ChallengeID != c.ChallengeID || t.Nonce != c.Nonce || t.ExpiresAt != strconv.FormatInt(c.ExpiresAt, 10) || t.SessionHash != p.SessionHash || t.ExpectedSequence != c.ExpectedSequence || t.PreviousTransitionHash != p.PreviousTransitionHash || t.OldRecoveryGeneration != p.OldRecoveryGeneration || t.OldRecoverySigningPublicKey != p.OldRecoverySigningPublicKey || t.OldRecoveryReceivingPublicKey != p.OldRecoveryReceivingPublicKey || t.NewRecoveryGeneration != p.NewRecoveryGeneration || t.NewRecoverySigningPublicKey != p.NewSigningPublicKey || t.NewRecoveryReceivingPublicKey != p.NewReceivingPublicKey || t.AuthorizationKind != p.AuthorizationKind || t.AuthorizerDeviceID != "" || !sameJSON(next.Transition.DependencyBundle, p.BaseBundle) || !sameJSON(sub.EnvironmentManifest, p.EnvironmentManifest) {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func (s *DAGRecoverySession) prepareIntent(id string) (DAGTransitionPreparation, error) {
	b, err := s.verifiedBindingLocked()
	if err != nil {
		return DAGTransitionPreparation{}, err
	}
	p := DAGTransitionPreparation{Version: 1, Kind: "transition-v2", AuthorizationKind: "old-recovery", Phase: "intent", Endpoint: b.Endpoint, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, Pin: b.Pin, InitializationHash: b.InitializationHash, InitializationProposalHash: b.InitializationProposalHash, SessionHash: b.SessionHash, OperationID: id, ExpectedSequence: s.vault.Sequence, OldRecoveryGeneration: b.RecoveryGeneration, PreviousTransitionHash: b.RecoveryHeadHash, OldRecoverySigningPublicKey: b.RecoverySigningPublicKey, OldRecoveryReceivingPublicKey: b.RecoveryReceivingPublicKey, BaseBundle: s.vault.DependencyBundle, EnvironmentManifest: []cryptox.RecoveryEnvironmentVersion{}}
	for _, row := range s.vault.Environments {
		p.EnvironmentManifest = append(p.EnvironmentManifest, cryptox.RecoveryEnvironmentVersion{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion})
	}
	sort.Slice(p.EnvironmentManifest, func(i, j int) bool {
		return p.EnvironmentManifest[i].EnvironmentID < p.EnvironmentManifest[j].EnvironmentID
	})
	if s.pending != nil {
		p.PriorOperationID, p.PriorContentHash, p.PriorAcceptedSequence = s.pending.OperationID, s.pending.ContentHash, s.pending.AcceptedSequence
	}
	return p, ValidateDAGTransitionPreparation(p)
}
func (s *DAGRecoverySession) saveOriginalIntent(id string) (DAGTransitionPreparation, error) {
	p, err := s.prepareIntent(id)
	if err != nil {
		return p, err
	}
	old, err := s.config.Preparation.LoadTransitionPreparation()
	if errors.Is(err, os.ErrNotExist) {
		return p, s.config.Preparation.SaveTransitionPreparation(p)
	}
	if err != nil {
		return p, err
	}
	if ValidateDAGTransitionPreparation(old) != nil || old.Phase != "intent" || !sameJSON(p, old) {
		return p, ErrDAGPreparationConflict
	}
	return old, nil
}
