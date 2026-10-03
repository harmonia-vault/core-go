package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

// 仅公有意图；不是已签原包、设备信任或可恢复的 bearer。
type DAGRecoveredPreparation struct {
	Version                    int                                  `json:"version"`
	Kind                       string                               `json:"kind"`
	Phase                      string                               `json:"phase"`
	Endpoint                   string                               `json:"endpoint"`
	AccountID                  string                               `json:"accountId"`
	AccountGeneration          uint64                               `json:"accountGeneration"`
	Pin                        cryptox.PinnedIssuerRoot             `json:"pin"`
	InitializationHash         string                               `json:"initializationHash"`
	InitializationProposalHash string                               `json:"initializationProposalHash"`
	RestrictedSessionHash      string                               `json:"restrictedSessionHash"`
	OperationID                string                               `json:"operationId"`
	ExpectedSequence           uint64                               `json:"expectedSequence"`
	RecoveryGeneration         string                               `json:"recoveryGeneration"`
	RecoveryHeadHash           string                               `json:"recoveryHeadHash"`
	RecoverySigningPublicKey   string                               `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string                               `json:"recoveryReceivingPublicKey"`
	DeviceID                   string                               `json:"deviceId"`
	DeviceSigningPublicKey     string                               `json:"deviceSigningPublicKey"`
	DeviceReceivingPublicKey   string                               `json:"deviceReceivingPublicKey"`
	BaseBundle                 cryptox.RecoveryDependencyBundle     `json:"baseBundle"`
	EnvironmentManifest        []cryptox.RecoveryEnvironmentVersion `json:"environmentManifest"`
	SelectedRights             []cryptox.RecoveredDeviceRight       `json:"selectedRights"`
	SelectedRightsHash         string                               `json:"selectedRightsHash"`
	PriorOperationID           string                               `json:"priorOperationId"`
	PriorContentHash           string                               `json:"priorContentHash"`
	PriorAcceptedSequence      uint64                               `json:"priorAcceptedSequence"`
	Challenge                  *DAGDeviceChallenge                  `json:"challenge,omitempty"`
}
type DAGRecoveredPreparationStore interface {
	LoadRecoveredPreparation() (DAGRecoveredPreparation, error)
	SaveRecoveredPreparation(DAGRecoveredPreparation) error
}
type DAGRecoveredChoices struct {
	Sequence         uint64                               `json:"sequence"`
	RecoveryHeadHash string                               `json:"recoveryHeadHash"`
	Environments     []cryptox.RecoveryEnvironmentVersion `json:"environments"`
}
type DAGRecoveredSelectionIntent struct {
	ExpectedSequence uint64
	RecoveryHeadHash string
	SelectedRights   []cryptox.RecoveredDeviceRight
}

func DecodeDAGRecoveredPreparation(raw []byte) (DAGRecoveredPreparation, error) {
	var p DAGRecoveredPreparation
	if len(raw) == 0 || len(raw) > MaxDAGPreparationBytes || cryptox.ValidateStrictJSON(raw, MaxDAGPreparationBytes) != nil {
		return p, cryptox.ErrInvalidWire
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !exactDAGRecoveredPreparationJSON(raw, p) {
		return p, cryptox.ErrInvalidWire
	}
	if err := ValidateDAGRecoveredPreparation(p); err != nil {
		return DAGRecoveredPreparation{}, err
	}
	return p, nil
}

// encoding/json accepts case-folded field names; DisallowUnknownFields alone
// therefore does not define this exact wire schema. Compare every raw object
// against the typed wire shape before semantic/cryptographic validation. The
// typed marshaler preserves required canonical nulls and omits optional fields;
// it cannot turn an omitted required field or a case alias into valid input.
func exactDAGRecoveredPreparationJSON(raw []byte, p DAGRecoveredPreparation) bool {
	canonical, err := json.Marshal(p)
	if err != nil || len(canonical) > MaxDAGPreparationBytes {
		return false
	}
	decode := func(data []byte) (any, error) {
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		var value any
		err := d.Decode(&value)
		return value, err
	}
	actual, err := decode(raw)
	if err != nil {
		return false
	}
	expected, err := decode(canonical)
	return err == nil && sameDAGRecoveredJSONShape(actual, expected, 1)
}
func sameDAGRecoveredJSONShape(actual, expected any, depth int) bool {
	if depth > cryptox.MaxStrictJSONDepth {
		return false
	}
	switch want := expected.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok || len(got) != len(want) {
			return false
		}
		for key, value := range want {
			found, exists := got[key]
			if !exists || !sameDAGRecoveredJSONShape(found, value, depth+1) {
				return false
			}
		}
		return true
	case []any:
		got, ok := actual.([]any)
		if !ok || len(got) != len(want) {
			return false
		}
		for i, value := range want {
			if !sameDAGRecoveredJSONShape(got[i], value, depth+1) {
				return false
			}
		}
		return true
	case nil:
		return actual == nil
	case string:
		_, ok := actual.(string)
		return ok
	case json.Number:
		_, ok := actual.(json.Number)
		return ok
	case bool:
		_, ok := actual.(bool)
		return ok
	default:
		return false
	}
}

func ValidateDAGRecoveredPreparation(p DAGRecoveredPreparation) error {
	if p.Version != 1 || p.Kind != "recovered-v2" || validateDAGJournalBinding(DAGJournalBinding{Endpoint: p.Endpoint, AccountID: p.AccountID, AccountGeneration: p.AccountGeneration}) != nil || p.Pin.AccountID != p.AccountID || p.Pin.AccountGeneration != strconv.FormatUint(p.AccountGeneration, 10) || !enrollmentID.MatchString(p.OperationID) || !enrollmentID.MatchString(p.DeviceID) || !dagHex(p.RestrictedSessionHash) || p.ExpectedSequence == 0 || p.ExpectedSequence >= 9007199254740991 || !enrollmentID.MatchString(p.PriorOperationID) || p.PriorOperationID == p.OperationID || !dagHex(p.PriorContentHash) || p.PriorAcceptedSequence == 0 || p.PriorAcceptedSequence > p.ExpectedSequence {
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
	if initial != p.InitializationHash || p.InitializationProposalHash != p.BaseBundle.Initialization.Proof.ProposalHash || p.RecoveryGeneration != head.RecoveryGeneration || p.RecoveryHeadHash != head.TransitionHead || p.RecoverySigningPublicKey != head.SigningPublicKey || p.RecoveryReceivingPublicKey != head.ReceivingPublicKey || head.AcceptedSequence > p.ExpectedSequence || p.PriorContentHash != p.RecoveryHeadHash {
		return cryptox.ErrInvalidWire
	}
	found := false
	for _, r := range p.BaseBundle.Records {
		if r.Kind != "transition-v2" || r.TransitionV2 == nil {
			continue
		}
		a := r.TransitionV2
		t := a.Submission.Transition
		h, e := cryptox.RecoveryTransitionHashV2(a.Submission)
		if e != nil {
			return e
		}
		if h == p.PriorContentHash {
			if t.OperationID != p.PriorOperationID || a.Sequence != p.PriorAcceptedSequence || t.SessionHash != p.RestrictedSessionHash || t.AuthorizationKind != "old-recovery" || t.ChainMode != "continuous" {
				return cryptox.ErrInvalidWire
			}
			found = true
		}
	}
	if !found {
		return cryptox.ErrInvalidWire
	}
	for _, key := range []string{p.DeviceSigningPublicKey, p.DeviceReceivingPublicKey} {
		if _, err := cryptox.DecodeBase64(key, 32, 32); err != nil {
			return err
		}
		if key == p.RecoverySigningPublicKey || key == p.RecoveryReceivingPublicKey {
			return cryptox.ErrInvalidWire
		}
	}
	if p.DeviceSigningPublicKey == p.DeviceReceivingPublicKey {
		return cryptox.ErrInvalidWire
	}
	if _, err := cryptox.RecoveryManifestHash(p.EnvironmentManifest); err != nil {
		return err
	}
	if len(p.SelectedRights) == 0 || len(p.SelectedRights) > 16 {
		return cryptox.ErrInvalidWire
	}
	h, err := cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
	if err != nil || h != p.SelectedRightsHash {
		return cryptox.ErrInvalidWire
	}
	versions := map[string]string{}
	for _, e := range p.EnvironmentManifest {
		versions[e.EnvironmentID] = e.KeyVersion
	}
	for _, r := range p.SelectedRights {
		if versions[r.EnvironmentID] != r.KeyVersion {
			return cryptox.ErrInvalidWire
		}
	}
	switch p.Phase {
	case "intent":
		if p.Challenge != nil {
			return cryptox.ErrInvalidWire
		}
	case "challenged":
		c := p.Challenge
		if c == nil || !enrollmentID.MatchString(c.ChallengeID) || c.ExpiresAt <= 0 {
			return cryptox.ErrInvalidWire
		}
		if _, err := cryptox.DecodeBase64(c.Nonce, 32, 32); err != nil {
			return err
		}
		if c.OperationID != p.OperationID || c.AccountGeneration != p.Pin.AccountGeneration || c.RestrictedSessionHash != p.RestrictedSessionHash || c.ExpectedSequence != strconv.FormatUint(p.ExpectedSequence, 10) || c.RecoveryGeneration != p.RecoveryGeneration || c.RecoveryTransitionHash != p.RecoveryHeadHash || c.DeviceID != p.DeviceID || c.DeviceSigningPublicKey != p.DeviceSigningPublicKey || c.DeviceReceivingPublicKey != p.DeviceReceivingPublicKey || !sameJSON(c.DependencyBundle, p.BaseBundle) {
			return cryptox.ErrInvalidWire
		}
		proof, err := proofFromDAGSource(p.Pin, c.DependencyBundle, c.IssuerEvidence)
		if err != nil {
			return err
		}
		if _, err = cryptox.VerifyIssuerRecoveryDAG(p.Pin, proof); err != nil {
			return err
		}
	default:
		return cryptox.ErrInvalidWire
	}
	return nil
}
func DAGRecoveredPreparationSameIntent(a, b DAGRecoveredPreparation) bool {
	a.Phase, b.Phase = "intent", "intent"
	a.Challenge, b.Challenge = nil, nil
	return sameJSON(a, b)
}
func ValidateDAGRecoveredPromotion(p DAGRecoveredPreparation, next ProtectedDAGOperation) error {
	if ValidateDAGRecoveredPreparation(p) != nil || p.Phase != "challenged" || validateProtectedDAGOperation(next) != nil || next.Kind != "recovered-v2" || next.Recovered == nil || next.Attempted || next.AcceptedSequence != 0 || next.Applied || next.Endpoint != p.Endpoint || next.AccountID != p.AccountID || next.AccountGeneration != p.AccountGeneration || next.Pin != p.Pin || next.OperationID != p.OperationID {
		return cryptox.ErrInvalidWire
	}
	s := next.Recovered.Submission
	e, c := s.Enrollment, p.Challenge
	if e.ChallengeID != c.ChallengeID || e.Nonce != c.Nonce || e.ExpiresAt != strconv.FormatInt(c.ExpiresAt, 10) || e.RestrictedSessionHash != p.RestrictedSessionHash || e.ExpectedSequence != c.ExpectedSequence || e.RecoveryGeneration != p.RecoveryGeneration || e.RecoveryTransitionHash != p.RecoveryHeadHash || e.DeviceID != p.DeviceID || e.DeviceSigningPublicKey != p.DeviceSigningPublicKey || e.DeviceReceivingPublicKey != p.DeviceReceivingPublicKey || e.SelectedRightsHash != p.SelectedRightsHash || !sameJSON(s.SelectedRights, p.SelectedRights) || !sameJSON(s.IssuerEvidence, c.IssuerEvidence) || !sameJSON(next.Recovered.DependencyBundle, p.BaseBundle) {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func (s *DAGRecoverySession) RecoveredDeviceChoices(ctx context.Context) (DAGRecoveredChoices, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return DAGRecoveredChoices{}, e
	}
	if s.vault.RotationRequired || s.pending == nil || !s.pending.Applied || s.pending.Kind != "transition-v2" || s.transitionChallenge != nil {
		return DAGRecoveredChoices{}, ErrDAGRecoveryState
	}
	if e := s.refresh(ctx); e != nil {
		return DAGRecoveredChoices{}, e
	}
	return s.recoveredChoices(), nil
}
func (s *DAGRecoverySession) recoveredChoices() DAGRecoveredChoices {
	v := DAGRecoveredChoices{Sequence: s.vault.Sequence, RecoveryHeadHash: s.vault.RecoveryHeadHash, Environments: []cryptox.RecoveryEnvironmentVersion{}}
	for _, e := range s.vault.Environments {
		v.Environments = append(v.Environments, cryptox.RecoveryEnvironmentVersion{EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion})
	}
	sort.Slice(v.Environments, func(i, j int) bool { return v.Environments[i].EnvironmentID < v.Environments[j].EnvironmentID })
	return v
}
func (s *DAGRecoverySession) recoveredIntent(id, deviceID, pub, recv string, in DAGRecoveredSelectionIntent) (DAGRecoveredPreparation, error) {
	b, err := s.verifiedBindingLocked()
	if err != nil {
		return DAGRecoveredPreparation{}, err
	}
	if b.RotationRequired || s.pending == nil || !s.pending.Applied || s.pending.Kind != "transition-v2" || in.ExpectedSequence != s.vault.Sequence || in.RecoveryHeadHash != s.vault.RecoveryHeadHash {
		return DAGRecoveredPreparation{}, ErrDAGPreparationConflict
	}
	rights := append([]cryptox.RecoveredDeviceRight(nil), in.SelectedRights...)
	sort.Slice(rights, func(i, j int) bool { return rights[i].EnvironmentID < rights[j].EnvironmentID })
	h, err := cryptox.RecoveredDeviceRightsHash(rights)
	if err != nil {
		return DAGRecoveredPreparation{}, err
	}
	p := DAGRecoveredPreparation{Version: 1, Kind: "recovered-v2", Phase: "intent", Endpoint: b.Endpoint, AccountID: b.AccountID, AccountGeneration: b.AccountGeneration, Pin: b.Pin, InitializationHash: b.InitializationHash, InitializationProposalHash: b.InitializationProposalHash, RestrictedSessionHash: b.SessionHash, OperationID: id, ExpectedSequence: s.vault.Sequence, RecoveryGeneration: b.RecoveryGeneration, RecoveryHeadHash: b.RecoveryHeadHash, RecoverySigningPublicKey: b.RecoverySigningPublicKey, RecoveryReceivingPublicKey: b.RecoveryReceivingPublicKey, DeviceID: deviceID, DeviceSigningPublicKey: pub, DeviceReceivingPublicKey: recv, BaseBundle: s.vault.DependencyBundle, EnvironmentManifest: s.recoveredChoices().Environments, SelectedRights: rights, SelectedRightsHash: h, PriorOperationID: s.pending.OperationID, PriorContentHash: s.pending.ContentHash, PriorAcceptedSequence: s.pending.AcceptedSequence}
	if err = ValidateDAGRecoveredPreparation(p); err != nil {
		return p, err
	}
	for _, r := range rights {
		expiry, e := strconv.ParseInt(r.ExpiresAt, 10, 64)
		if e != nil || expiry != 0 && expiry <= s.config.Now().Unix() {
			return p, cryptox.ErrInvalidWire
		}
	}
	return p, nil
}
func (s *DAGRecoverySession) saveRecoveredIntent(p DAGRecoveredPreparation) (DAGRecoveredPreparation, error) {
	old, e := s.config.RecoveredPreparation.LoadRecoveredPreparation()
	if errors.Is(e, os.ErrNotExist) {
		return p, s.config.RecoveredPreparation.SaveRecoveredPreparation(p)
	}
	if e != nil {
		return p, e
	}
	if ValidateDAGRecoveredPreparation(old) != nil || !DAGRecoveredPreparationSameIntent(p, old) {
		return p, ErrDAGPreparationConflict
	}
	return old, nil
}
