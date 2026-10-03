package mobileworkflow

import (
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

// This capability has its own vault shape. A legacy response never supplies a
// replacement genesis, transition or authenticated current recovery public key.
type recoveryAuthorityVault struct {
	recoveryVaultWire
	Transitions []cryptox.AcceptedRecoveryTransition `json:"transitions"`
}

type recoveryAuthorityChallenge struct {
	ChallengeID                   string                               `json:"challengeId"`
	Nonce                         string                               `json:"nonce"`
	ExpiresAt                     int64                                `json:"expiresAt"`
	SessionHash                   string                               `json:"sessionHash"`
	ExpectedSequence              string                               `json:"expectedSequence"`
	PreviousTransitionHash        string                               `json:"previousTransitionHash"`
	OldRecoveryGeneration         string                               `json:"oldRecoveryGeneration"`
	OldRecoverySigningPublicKey   string                               `json:"oldRecoverySigningPublicKey"`
	OldRecoveryReceivingPublicKey string                               `json:"oldRecoveryReceivingPublicKey"`
	EnvironmentManifest           []cryptox.RecoveryEnvironmentVersion `json:"environmentManifest"`
	AuthoritySet                  []cryptox.RecoveryAdminAuthority     `json:"authoritySet"`
	IssuerEvidence                *cryptox.IssuerProofV2               `json:"issuerEvidence"`
	LegacyState                   *cryptox.RecoveryLegacyState         `json:"legacyState"`
	OriginalInitialization        cryptox.OriginalInitialization       `json:"originalInitialization"`
	Transitions                   []cryptox.AcceptedRecoveryTransition `json:"transitions"`
}
type recoveryAuthorityStatus struct {
	OperationID            string `json:"operationId"`
	Accepted               bool   `json:"accepted"`
	Sequence               uint64 `json:"sequence,omitempty"`
	ContentHash            string `json:"contentHash,omitempty"`
	TransitionHash         string `json:"transitionHash,omitempty"`
	RecoveryEnrollmentHash string `json:"recoveryEnrollmentHash,omitempty"`
}
type recoveryAuthorityReceipt struct {
	Sequence               uint64 `json:"sequence"`
	Replayed               bool   `json:"replayed"`
	ContentHash            string `json:"contentHash"`
	TransitionHash         string `json:"transitionHash,omitempty"`
	RecoveryEnrollmentHash string `json:"recoveryEnrollmentHash,omitempty"`
}

func recoveryAuthorityPin(v recoveryVaultWire) (cryptox.PinnedIssuerRoot, error) {
	if v.TrustRoot == nil {
		return cryptox.PinnedIssuerRoot{}, ErrRecoveryEvidence
	}
	root := v.TrustRoot
	return cryptox.PinnedIssuerRoot{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}, nil
}
func recoveryOriginalRecord(v recoveryVaultWire) (cryptox.OriginalInitialization, error) {
	i := v.OriginalInitialization
	if i == nil {
		return cryptox.OriginalInitialization{}, ErrRecoveryEvidence
	}
	return cryptox.OriginalInitialization{Proposal: i.Proposal, Proof: i.Proof, DeviceSignature: i.DeviceSignature, RecoverySignature: i.RecoverySignature, Sequence: i.Sequence}, nil
}

// The caller must first authenticate current TrustRoot from complete-code keys
// or its prior protected context. A server directory is never the supplied pin.
func verifyRecoveryAuthorityChain(v recoveryAuthorityVault) (*cryptox.VerifiedRecoveryAuthority, error) {
	if v.Sequence == 0 || v.Sequence > 9007199254740991 || v.Transitions == nil || len(v.Transitions) > cryptox.MaxRecoveryTransitions {
		return nil, ErrRecoveryEvidence
	}
	pin, err := recoveryAuthorityPin(v.recoveryVaultWire)
	if err != nil {
		return nil, err
	}
	initial, err := recoveryOriginalRecord(v.recoveryVaultWire)
	if err != nil {
		return nil, err
	}
	authority, err := cryptox.VerifyRecoveryInitialization(pin, initial)
	if err != nil {
		return nil, errors.Join(ErrRecoveryEvidence, err)
	}
	last := initial.Sequence
	for _, r := range v.Transitions {
		if r.Sequence <= last || r.Sequence > v.Sequence {
			return nil, ErrRecoveryEvidence
		}
		authority, err = cryptox.VerifyAcceptedRecoveryTransition(authority, r)
		if err != nil {
			return nil, errors.Join(ErrRecoveryEvidence, err)
		}
		last = r.Sequence
	}
	// Current-code possession cannot fill a missing old/new continuity signature.
	if authority.Generation() != v.RecoveryGeneration || authority.SigningPublicKey() != v.RecoverySigningPublicKey || authority.ReceivingPublicKey() != v.RecoveryReceivingPublicKey || v.TrustRoot.RecoveryGeneration != v.RecoveryGeneration || v.TrustRoot.RecoverySigningPublicKey != v.RecoverySigningPublicKey || v.TrustRoot.RecoveryReceivingPublicKey != v.RecoveryReceivingPublicKey {
		return nil, ErrRecoveryEvidence
	}
	return authority, nil
}

// Typed transition envelopes are authenticated by both continuity and new-code
// signatures. The remaining current envelopes still require the original
// initialization, full manager-signed environment change or legacy 13-domain proof.
func verifyAuthorityEnvelopeCommitments(v recoveryAuthorityVault) (*cryptox.VerifiedRecoveryAuthority, error) {
	authority, err := verifyRecoveryAuthorityChain(v)
	if err != nil {
		return nil, err
	}
	proven := map[string]cryptox.RecoveryEnvelope{}
	for _, r := range v.Transitions {
		t := r.Submission.Transition
		if t.NewRecoveryGeneration == v.RecoveryGeneration && t.NewRecoverySigningPublicKey == v.RecoverySigningPublicKey && t.NewRecoveryReceivingPublicKey == v.RecoveryReceivingPublicKey && r.Submission.NewTrustRoot == *v.TrustRoot {
			for _, e := range r.Submission.Envelopes {
				proven[e.EnvironmentID] = e
			}
		}
	}
	remaining := clone(v.recoveryVaultWire)
	remaining.Environments = []cryptox.RecoveryEnvelope{}
	seen := map[string]bool{}
	for _, e := range v.Environments {
		if seen[e.EnvironmentID] {
			return nil, ErrRecoveryEvidence
		}
		seen[e.EnvironmentID] = true
		if p, ok := proven[e.EnvironmentID]; !ok || p != e {
			remaining.Environments = append(remaining.Environments, e)
		}
	}
	if remaining.EnvelopeEvidence != nil {
		only := map[string]bool{}
		for _, e := range remaining.Environments {
			only[e.EnvironmentID] = true
		}
		sources := remaining.EnvelopeEvidence.EnvironmentChanges[:0]
		for _, s := range remaining.EnvelopeEvidence.EnvironmentChanges {
			if only[s.Change.Change.EnvironmentID] {
				sources = append(sources, s)
			}
		}
		remaining.EnvelopeEvidence.EnvironmentChanges = sources
	}
	if err := verifyRecoveryEnvelopes(remaining, *v.TrustRoot, true); err != nil {
		return nil, err
	}
	return authority, nil
}

func verifyAuthorityReceipt(r recoveryAuthorityReceipt, id, hash, expected string, recovered bool) error {
	base, err := strconv.ParseUint(expected, 10, 64)
	decoded, hashErr := hex.DecodeString(hash)
	if err != nil || hashErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash || strconv.FormatUint(base, 10) != expected || base >= 9007199254740991 || r.Sequence != base+1 || r.ContentHash != hash || !identifier.MatchString(id) {
		return ErrRecoveryEvidence
	}
	if recovered {
		if r.RecoveryEnrollmentHash != hash || r.TransitionHash != "" {
			return ErrRecoveryEvidence
		}
	} else if r.TransitionHash != hash || r.RecoveryEnrollmentHash != "" {
		return ErrRecoveryEvidence
	}
	return nil
}

type recoveryAuthorityRecord struct {
	Version int                       `json:"version"`
	Vault   recoveryAuthorityVault    `json:"vault"`
	Pending *recoveryAuthorityPending `json:"pending,omitempty"`
}
type recoveryAuthorityPending struct {
	Applied          bool                                 `json:"applied,omitempty"`
	CreatedAt        int64                                `json:"createdAt"`
	BaseSequence     uint64                               `json:"baseSequence"`
	Packet           cryptox.RecoveryTransitionSubmission `json:"packet"`
	ContentHash      string                               `json:"contentHash,omitempty"`
	AcceptedSequence uint64                               `json:"acceptedSequence,omitempty"`
	DeadlineClosed   bool                                 `json:"deadlineClosed,omitempty"`
}

func (w *Workflow) verifyAuthorityVault(v recoveryAuthorityVault, root cryptox.TrustRoot, keys map[string]string) ([]RecoveredEnvironment, error) {
	base := v.recoveryVaultWire
	if base.AccountID != w.state.AccountID || base.AccountGeneration != w.state.AccountGeneration || base.Sequence == 0 || base.Sequence > 9007199254740991 || len(base.Environments) == 0 || len(base.Environments) > 256 || len(base.Environments) != len(keys) || base.TrustRoot == nil || *base.TrustRoot != root {
		return nil, ErrRecoveryEvidence
	}
	if _, err := verifyAuthorityEnvelopeCommitments(v); err != nil {
		return nil, err
	}
	accepted, err := w.verifyRecoveryOriginGrants(base, root)
	if err != nil {
		return nil, err
	}
	return w.verifyRecoveryVaultData(base, root, keys, true, accepted)
}
func (w *Workflow) validateRecoveryAuthorityRecord() error {
	a, r := w.state.RecoveryAuthority, w.state.Recovery
	if a == nil {
		return nil
	}
	if r == nil || a.Version != 1 || !r.OriginsRequired || r.Rotation != nil || w.state.Root != nil {
		return ErrRecoveryRestricted
	}
	if !reflect.DeepEqual(a.Vault.recoveryVaultWire, r.Vault) {
		return ErrRecoveryEvidence
	}
	if r.SessionClosed {
		if len(r.Keys) != 0 || len(r.Vault.Events) != 0 {
			return ErrRecoveryEvidence
		}
		if _, err := verifyAuthorityEnvelopeCommitments(a.Vault); err != nil {
			return err
		}
		if _, err := w.verifyRecoveryOriginGrants(r.Vault, r.Root); err != nil {
			return err
		}
	} else if _, err := w.verifyAuthorityVault(a.Vault, r.Root, r.Keys); err != nil {
		return err
	}
	p := a.Pending
	if p == nil {
		return nil
	}
	t := p.Packet.Transition
	if p.CreatedAt < r.CreatedAt || p.BaseSequence != parseAuthoritySequence(t.ExpectedSequence) || t.AccountID != r.AccountID || t.AccountGeneration != r.AccountGeneration || t.SessionHash != r.SessionHash || t.AuthorizationKind != "old-recovery" || t.ChainMode != "continuous" || t.AuthorizerDeviceID != "" || p.Packet.LegacyState != nil || p.Packet.IssuerEvidence != nil || p.Packet.AuthoritySet == nil || len(p.Packet.AuthoritySet) != 0 {
		return ErrRecoveryEvidence
	}
	if _, err := t.SigningBytes(); err != nil {
		return err
	}
	if len(p.Packet.Envelopes) != len(p.Packet.EnvironmentManifest) {
		return ErrRecoveryEvidence
	}
	if h, err := cryptox.RecoveryManifestHash(p.Packet.EnvironmentManifest); err != nil || h != t.EnvironmentManifestHash {
		return ErrRecoveryEvidence
	}
	if h, err := cryptox.RecoveryTransitionEnvelopesHash(p.Packet.Envelopes); err != nil || h != t.EnvelopesHash {
		return ErrRecoveryEvidence
	}
	if h, err := cryptox.RecoveryTrustRootReferenceHash(r.AccountID, r.AccountGeneration, p.Packet.NewTrustRoot); err != nil || h != t.NewTrustRootHash {
		return ErrRecoveryEvidence
	}
	if (p.Packet.AuthorizationSignature == "") != (p.Packet.NewRecoverySignature == "") {
		return ErrRecoveryEvidence
	}
	pin, err := recoveryAuthorityPin(a.Vault.recoveryVaultWire)
	if err != nil {
		return err
	}
	original, err := recoveryOriginalRecord(a.Vault.recoveryVaultWire)
	if err != nil {
		return err
	}
	prior, err := cryptox.VerifyRecoveryInitialization(pin, original)
	if err != nil {
		return err
	}
	acceptedExact := false
	for _, accepted := range a.Vault.Transitions {
		if accepted.Submission.Transition.OperationID == t.OperationID {
			if !sameJSONValue(accepted.Submission, p.Packet) || accepted.Sequence != p.AcceptedSequence {
				return ErrRecoveryEvidence
			}
			acceptedExact = true
			break
		}
		prior, err = cryptox.VerifyAcceptedRecoveryTransition(prior, accepted)
		if err != nil {
			return err
		}
	}
	if t.PreviousTransitionHash != prior.HeadHash() || t.OldRecoveryGeneration != prior.Generation() || t.OldRecoverySigningPublicKey != prior.SigningPublicKey() || t.OldRecoveryReceivingPublicKey != prior.ReceivingPublicKey() || p.Packet.NewTrustRoot.RootDeviceID != r.Root.RootDeviceID || p.Packet.NewTrustRoot.RootSigningPublicKey != r.Root.RootSigningPublicKey || p.Packet.NewTrustRoot.RootReceivingPublicKey != r.Root.RootReceivingPublicKey || p.Packet.NewTrustRoot.RecoveryGeneration != t.NewRecoveryGeneration || p.Packet.NewTrustRoot.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || p.Packet.NewTrustRoot.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey {
		return ErrRecoveryEvidence
	}
	newPub, err := cryptox.DecodeBase64(t.NewRecoverySigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyTrustRoot(r.AccountID, r.AccountGeneration, p.Packet.NewTrustRoot, newPub) != nil {
		return ErrRecoveryEvidence
	}
	manifest := []cryptox.RecoveryEnvironmentVersion{}
	for _, e := range r.Vault.Environments {
		manifest = append(manifest, cryptox.RecoveryEnvironmentVersion{EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion})
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].EnvironmentID < manifest[j].EnvironmentID })
	if !sameJSONValue(manifest, p.Packet.EnvironmentManifest) {
		return ErrRecoveryEvidence
	}
	for i, e := range p.Packet.Envelopes {
		if e.EnvironmentID != manifest[i].EnvironmentID || e.KeyVersion != manifest[i].KeyVersion {
			return ErrRecoveryEvidence
		}
	}
	if p.Applied && (!acceptedExact || p.AcceptedSequence == 0 || a.Vault.Sequence < p.AcceptedSequence || a.Vault.RotationRequired || r.Root != p.Packet.NewTrustRoot || !sameRecoveryEnvelopeSet(a.Vault.Environments, p.Packet.Envelopes)) {
		return ErrRecoveryEvidence
	}
	if p.Packet.AuthorizationSignature != "" {
		if h, err := cryptox.RecoveryTransitionHash(p.Packet); err != nil || h != p.ContentHash {
			return ErrRecoveryEvidence
		}
		pin, err := recoveryAuthorityPin(a.Vault.recoveryVaultWire)
		if err != nil {
			return err
		}
		original, err := recoveryOriginalRecord(a.Vault.recoveryVaultWire)
		if err != nil {
			return err
		}
		authority, err := cryptox.VerifyRecoveryInitialization(pin, original)
		if err != nil {
			return err
		}
		for _, accepted := range a.Vault.Transitions {
			if accepted.Submission.Transition.OperationID == t.OperationID {
				break
			}
			authority, err = cryptox.VerifyAcceptedRecoveryTransition(authority, accepted)
			if err != nil {
				return err
			}
		}
		if _, err = cryptox.VerifyAcceptedRecoveryTransition(authority, cryptox.AcceptedRecoveryTransition{Submission: p.Packet, Sequence: p.BaseSequence + 1}); err != nil {
			return err
		}
	} else if p.ContentHash != "" || p.AcceptedSequence != 0 {
		return ErrRecoveryEvidence
	}
	if p.AcceptedSequence != 0 && p.AcceptedSequence != p.BaseSequence+1 {
		return ErrRecoveryEvidence
	}
	return nil
}
func parseAuthoritySequence(s string) uint64 {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		return ^uint64(0)
	}
	return n
}

func sameRecoveryEnvelopeSet(a, b []cryptox.RecoveryEnvelope) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]cryptox.RecoveryEnvelope(nil), a...)
	b = append([]cryptox.RecoveryEnvelope(nil), b...)
	sort.Slice(a, func(i, j int) bool { return a[i].EnvironmentID < a[j].EnvironmentID })
	sort.Slice(b, func(i, j int) bool { return b[i].EnvironmentID < b[j].EnvironmentID })
	for i := range a {
		if a[i] != b[i] || i > 0 && (a[i-1].EnvironmentID == a[i].EnvironmentID || b[i-1].EnvironmentID == b[i].EnvironmentID) {
			return false
		}
	}
	return true
}
