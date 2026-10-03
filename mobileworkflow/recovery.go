package mobileworkflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var ErrRecoveryRestricted = errors.New("recovery context is restricted; it does not enroll or authorize this device")
var ErrRecoveryPending = errors.New("recovery rotation outcome pending; query the original operation")
var ErrRecoveryExpired = errors.New("original recovery session or rotation challenge expired; no implicit replacement")
var ErrRecoveryEvidence = errors.New("recovery historical issuer evidence is unavailable or invalid")

// RecoveryInfo is safe metadata. A completed rotation never makes a device trusted.
type RecoveryInfo struct {
	State              string `json:"state"`
	TrustedDevice      bool   `json:"trustedDevice"`
	RotationRequired   bool   `json:"rotationRequired"`
	RecoveryGeneration string `json:"recoveryGeneration,omitempty"`
	Sequence           uint64 `json:"sequence,omitempty"`
	Environments       int    `json:"environments,omitempty"`
	ID                 string `json:"id,omitempty"`
	ExpiresAt          int64  `json:"expiresAt,omitempty"`
}
type RecoveryView struct {
	Info         RecoveryInfo           `json:"info"`
	Environments []RecoveredEnvironment `json:"environments"`
}
type RecoveredEnvironment struct {
	ID         string            `json:"id"`
	KeyVersion string            `json:"keyVersion"`
	Variables  map[string]string `json:"variables"`
}
type recoveryGrantEvent struct {
	OriginHash    string                  `json:"originHash,omitempty"`
	Sequence      uint64                  `json:"sequence"`
	Grant         syncclient.SignedGrant  `json:"grant"`
	Authorization *syncclient.SignedGrant `json:"authorization"`
}
type recoveryDevice struct {
	ID                 string `json:"id"`
	SigningPublicKey   string `json:"signingPublicKey"`
	ReceivingPublicKey string `json:"receivingPublicKey"`
	Revoked            bool   `json:"revoked"`
}

// Historical initialization proof binds the exact original environment set and
// both original recovery keys to the current recovery-authenticated root device.
// The current recovery keys may legitimately differ after a complete rotation.
type recoveryOriginalInitialization struct {
	Proposal          cryptox.InitializationProposal `json:"proposal"`
	Proof             cryptox.InitializationProof    `json:"proof"`
	DeviceSignature   string                         `json:"deviceSignature"`
	RecoverySignature string                         `json:"recoverySignature"`
	Sequence          uint64                         `json:"sequence"`
}

type recoveryVaultWire struct {
	EnvelopeEvidence           *recoveryEnvelopeEvidence       `json:"envelopeEvidence,omitempty"`
	IssuerEvidence             json.RawMessage                 `json:"issuerEvidence,omitempty"`
	OriginalInitialization     *recoveryOriginalInitialization `json:"originalInitialization,omitempty"`
	AccountID                  string                          `json:"accountId"`
	AccountGeneration          string                          `json:"accountGeneration"`
	RecoveryGeneration         string                          `json:"recoveryGeneration"`
	RecoverySigningPublicKey   string                          `json:"recoverySigningPublicKey"`
	RecoveryReceivingPublicKey string                          `json:"recoveryReceivingPublicKey"`
	RotationRequired           bool                            `json:"rotationRequired"`
	Sequence                   uint64                          `json:"sequence"`
	TrustRoot                  *cryptox.TrustRoot              `json:"trustRoot"`
	PublicDevices              []recoveryDevice                `json:"publicDevices"`
	CurrentGrants              []syncclient.SignedGrant        `json:"currentGrants"`
	GrantHistory               []recoveryGrantEvent            `json:"grantHistory"`
	Environments               []cryptox.RecoveryEnvelope      `json:"environments"`
	Events                     []syncclient.Event              `json:"events"`
}
type recoveryChallengeWire struct {
	ChallengeID        string   `json:"challengeId"`
	Nonce              string   `json:"nonce"`
	ExpiresAt          int64    `json:"expiresAt"`
	RecoveryGeneration string   `json:"recoveryGeneration"`
	SigningPayload     []string `json:"signingPayload"`
}
type recoveryRotationWire struct {
	State                 string   `json:"state"`
	IdempotencyKey        string   `json:"idempotencyKey"`
	ChallengeID           string   `json:"challengeId,omitempty"`
	Nonce                 string   `json:"nonce,omitempty"`
	ExpiresAt             int64    `json:"expiresAt,omitempty"`
	RecoveryGeneration    string   `json:"recoveryGeneration,omitempty"`
	NewRecoveryGeneration string   `json:"newRecoveryGeneration,omitempty"`
	EnvelopesHash         string   `json:"envelopesHash,omitempty"`
	TrustRootHash         *string  `json:"trustRootHash,omitempty"`
	Sequence              *uint64  `json:"sequence,omitempty"`
	SigningPayload        []string `json:"signingPayload,omitempty"`
	Replayed              bool     `json:"replayed,omitempty"`
}
type recoveryRotationRecord struct {
	DeadlineClosed   bool                             `json:"deadlineClosed,omitempty"`
	PriorRoot        cryptox.TrustRoot                `json:"priorRoot"`
	Proposal         cryptox.RecoveryRotationProposal `json:"proposal"`
	CreatedAt        int64                            `json:"createdAt"`
	BaseSequence     uint64                           `json:"baseSequence"`
	Challenge        *recoveryRotationWire            `json:"challenge,omitempty"`
	Signature        string                           `json:"signature,omitempty"`
	AcceptedSequence uint64                           `json:"acceptedSequence,omitempty"`
}

// Only native authenticated AES storage may retain this restricted cache/token.
// Recovery seeds, codes, password-derived credentials and device private keys are absent.
type recoveryRecord struct {
	OriginsRequired    bool                    `json:"originsRequired,omitempty"`
	SessionHash        string                  `json:"sessionHash"`
	SessionClosed      bool                    `json:"sessionClosed,omitempty"`
	LastObservedAt     int64                   `json:"lastObservedAt"`
	Version            int                     `json:"version"`
	AccountID          string                  `json:"accountId"`
	AccountGeneration  string                  `json:"accountGeneration"`
	CreatedAt          int64                   `json:"createdAt"`
	SessionToken       string                  `json:"sessionToken"`
	SessionExpiresAt   int64                   `json:"sessionExpiresAt"`
	RecoveryGeneration string                  `json:"recoveryGeneration"`
	SigningPublicKey   string                  `json:"signingPublicKey"`
	ReceivingPublicKey string                  `json:"receivingPublicKey"`
	Root               cryptox.TrustRoot       `json:"root"`
	Vault              recoveryVaultWire       `json:"vault"`
	Keys               map[string]string       `json:"keys"`
	Rotation           *recoveryRotationRecord `json:"rotation,omitempty"`
	RotationCompleted  bool                    `json:"rotationCompleted"`
}

func positiveDecimal(value string) bool {
	n, e := strconv.ParseUint(value, 10, 64)
	return e == nil && n > 0 && strconv.FormatUint(n, 10) == value
}
func (w *Workflow) recoveryOnly() error {
	if w.dagPersistenceFailed {
		return ErrDAGPersistence
	}
	if w.state.RecoveryDAG != nil {
		return ErrRecoveryRestricted
	}
	if w.closed {
		return ErrClosed
	}
	if len(w.state.SelfRevocation) > 0 {
		return ErrSelfRevocationPending
	}
	if w.state.Root != nil || w.state.Pending != nil || w.state.PendingApproval != nil || w.state.PendingApprovalV3 != nil || w.state.PendingApprovalV4 != nil || w.state.EnrollmentV3 != nil || w.engine.State().AccountClosed {
		return ErrRecoveryRestricted
	}
	return nil
}
func (w *Workflow) recoveryInfo() RecoveryInfo {
	if w.state.RecoveryAuthority != nil {
		return w.recoveryAuthorityInfo()
	}
	r := w.state.Recovery
	if r == nil {
		return RecoveryInfo{State: "none"}
	}
	info := RecoveryInfo{State: "rotation-required", RotationRequired: !r.RotationCompleted, RecoveryGeneration: r.RecoveryGeneration, Sequence: r.Vault.Sequence, Environments: len(r.Vault.Environments), ExpiresAt: r.SessionExpiresAt}
	if r.RotationCompleted {
		info.State = "rotation-complete-restricted"
	}
	if r.Rotation != nil && !r.RotationCompleted {
		info.State = "rotation-pending"
		info.ID = r.Rotation.Proposal.IdempotencyKey
		if r.Rotation.Challenge != nil {
			info.ExpiresAt = r.Rotation.Challenge.ExpiresAt
		}
	}
	if r.SessionClosed || r.SessionExpiresAt <= w.now().Unix() || r.Rotation != nil && !r.RotationCompleted && (r.Rotation.DeadlineClosed || r.Rotation.Challenge != nil && r.Rotation.Challenge.ExpiresAt <= w.now().Unix()) {
		info.State = "expired-pending"
	}
	return info
}

// Expiry observations are durable. Rolling the wall clock back must not reopen
// a nonce window or retain a previously expired recovery bearer.
func (w *Workflow) observeRecoveryClock() error {
	r := w.state.Recovery
	if r == nil {
		return nil
	}
	now := w.now().Unix()
	if now < r.CreatedAt-5 || now < r.LastObservedAt-5 {
		return errors.Join(ErrRecoveryExpired, w.closeRecoverySessionForClock())
	}
	changed := false
	if now > r.LastObservedAt {
		r.LastObservedAt = now
		changed = true
	}
	if !r.SessionClosed && now >= r.SessionExpiresAt {
		if err := w.closeRecoverySessionForClock(); err != nil {
			return err
		}
		changed = true
	}
	if q := r.Rotation; q != nil && !q.DeadlineClosed && q.Challenge != nil && now >= q.Challenge.ExpiresAt {
		q.DeadlineClosed = true
		changed = true
	}
	if changed {
		return w.persist()
	}
	return nil
}
func (w *Workflow) RecoveryInfo() (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryOnly(); err != nil {
		return RecoveryInfo{}, err
	}
	if err := w.observeRecoveryClock(); err != nil {
		return w.recoveryInfo(), err
	}
	return w.recoveryInfo(), nil
}
func (w *Workflow) recoveryLive() error {
	if err := w.recoveryOnly(); err != nil {
		return err
	}
	if w.state.Recovery == nil {
		return ErrRecoveryRestricted
	}
	if err := w.observeRecoveryClock(); err != nil {
		return err
	}
	if w.state.Recovery.SessionClosed || w.state.Recovery.SessionExpiresAt <= w.now().Unix() {
		return ErrRecoveryExpired
	}
	return nil
}
func (w *Workflow) validateRecoveryState() error {
	r := w.state.Recovery
	if r == nil {
		if w.state.RecoveryAuthority != nil {
			return ErrRecoveryEvidence
		}
		return nil
	}
	if err := w.recoveryOnly(); err != nil {
		return err
	}
	if r.Version != 1 || r.AccountID != w.state.AccountID || r.AccountGeneration != w.state.AccountGeneration || !identifier.MatchString(r.AccountID) || !positiveDecimal(r.AccountGeneration) || !positiveDecimal(r.RecoveryGeneration) || r.CreatedAt <= 0 || r.SessionExpiresAt <= r.CreatedAt || r.SessionExpiresAt > r.CreatedAt+905 {
		return errors.New("protected recovery account/session binding invalid")
	}
	if hash, err := hex.DecodeString(r.SessionHash); err != nil || len(hash) != 32 || hex.EncodeToString(hash) != r.SessionHash || r.LastObservedAt < r.CreatedAt {
		return errors.New("protected recovery session hash/clock invalid")
	}
	if r.SessionClosed {
		if r.SessionToken != "" {
			return errors.New("expired recovery retained bearer")
		}
	} else {
		if _, err := cryptox.DecodeBase64(r.SessionToken, 32, 32); err != nil {
			return errors.New("protected recovery session invalid")
		}
		hash := sha256.Sum256([]byte(r.SessionToken))
		if hex.EncodeToString(hash[:]) != r.SessionHash {
			return errors.New("protected recovery original session changed")
		}
	}
	if r.Root.RecoveryGeneration != r.RecoveryGeneration || r.Root.RecoverySigningPublicKey != r.SigningPublicKey || r.Root.RecoveryReceivingPublicKey != r.ReceivingPublicKey {
		return errors.New("protected recovery root binding invalid")
	}
	pub, err := cryptox.DecodeBase64(r.SigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyTrustRoot(r.AccountID, r.AccountGeneration, r.Root, pub) != nil {
		return errors.New("protected recovery root signature invalid")
	}
	if _, err = cryptox.DecodeBase64(r.ReceivingPublicKey, 32, 32); err != nil {
		return err
	}
	if w.state.RecoveryAuthority != nil {
		return w.validateRecoveryAuthorityRecord()
	}
	if r.SessionClosed {
		if err = w.validateClosedRecoveryVault(r); err != nil {
			return err
		}
	} else if _, err = w.verifyRecoveryVault(r.Vault, r.Root, r.Keys); err != nil {
		return err
	}
	if r.Vault.RecoveryGeneration != r.RecoveryGeneration || r.Vault.RotationRequired == r.RotationCompleted {
		return errors.New("protected recovery capability inconsistent")
	}
	if r.RotationCompleted && r.Rotation == nil {
		return errors.New("recovery boolean cannot replace completed rotation evidence")
	}
	if r.Rotation != nil {
		q := r.Rotation
		if !identifier.MatchString(q.Proposal.IdempotencyKey) || len(q.Proposal.IdempotencyKey) > 64 || q.CreatedAt < r.CreatedAt || q.BaseSequence > r.Vault.Sequence || q.Proposal.NewTrustRoot.RootDeviceID != r.Root.RootDeviceID || q.Proposal.NewTrustRoot.RootSigningPublicKey != r.Root.RootSigningPublicKey || q.Proposal.NewTrustRoot.RootReceivingPublicKey != r.Root.RootReceivingPublicKey {
			return errors.New("protected recovery rotation binding invalid")
		}
		if _, err := cryptox.RecoveryEnvelopesHash(q.Proposal.Envelopes); err != nil {
			return err
		}
		if len(q.Proposal.Envelopes) != len(r.Vault.Environments) {
			return errors.New("protected recovery proposal incomplete")
		}
		for _, e := range q.Proposal.Envelopes {
			found := false
			for _, v := range r.Vault.Environments {
				if e.EnvironmentID == v.EnvironmentID && e.KeyVersion == v.KeyVersion {
					found = true
					break
				}
			}
			if !found {
				return errors.New("protected recovery proposal environment/version changed")
			}
		}
		if q.Proposal.NewTrustRoot.RecoveryGeneration != q.Proposal.NewRecoveryGeneration || q.Proposal.NewTrustRoot.RecoverySigningPublicKey != q.Proposal.NewRecoverySigningPublicKey || q.Proposal.NewTrustRoot.RecoveryReceivingPublicKey != q.Proposal.NewRecoveryReceivingPublicKey {
			return errors.New("protected recovery proposal key binding invalid")
		}
		if _, err := q.Proposal.NewTrustRoot.Hash(r.AccountID, r.AccountGeneration); err != nil {
			return err
		}
		priorPub, err := cryptox.DecodeBase64(q.PriorRoot.RecoverySigningPublicKey, 32, 32)
		if err != nil || cryptox.VerifyTrustRoot(r.AccountID, r.AccountGeneration, q.PriorRoot, priorPub) != nil || q.PriorRoot.RootDeviceID != r.Root.RootDeviceID || q.PriorRoot.RootSigningPublicKey != r.Root.RootSigningPublicKey || q.PriorRoot.RootReceivingPublicKey != r.Root.RootReceivingPublicKey {
			return errors.New("protected rotation prior root invalid")
		}
		if !r.RotationCompleted && q.PriorRoot != r.Root {
			return errors.New("protected rotation prior root changed")
		}
		if q.Challenge != nil {
			proof, err := w.rotationProof(q, *q.Challenge)
			if err != nil {
				return err
			}
			if q.Signature != "" {
				newpub, err := cryptox.DecodeBase64(q.Proposal.NewRecoverySigningPublicKey, 32, 32)
				if err != nil || cryptox.VerifyRecoveryRotationProof(proof, q.Signature, newpub) != nil {
					return errors.New("protected recovery rotation signature invalid")
				}
			}
		} else if q.Signature != "" || q.AcceptedSequence != 0 {
			return errors.New("recovery receipt lacks challenge")
		}
		if r.RotationCompleted && (q.AcceptedSequence <= q.BaseSequence || q.AcceptedSequence > r.Vault.Sequence || q.Signature == "") {
			return errors.New("protected recovery acceptance invalid")
		}
	}
	return nil
}

// BeginRecovery requires Login in the same native authenticated operation. Login is only
// account discovery; the local complete recovery code independently pins the recovery root.
func (w *Workflow) BeginRecovery(ctx context.Context, completeCode string) (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.beginRecovery(ctx, completeCode, false)
}

// BeginRecoveryWithOrigins requires the exact original initialization commitment
// and full signed control graph. It never falls back to the legacy initial slice.
func (w *Workflow) BeginRecoveryWithOrigins(ctx context.Context, completeCode string) (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.beginRecovery(ctx, completeCode, true)
}
func (w *Workflow) beginRecovery(ctx context.Context, completeCode string, originsRequired bool, capture ...func(ed25519.PrivateKey) error) (RecoveryInfo, error) {
	if err := w.recoveryOnly(); err != nil {
		return RecoveryInfo{}, err
	}
	if w.state.Recovery != nil || w.login == nil || w.login.ExpiresAt <= w.now().Unix() {
		return RecoveryInfo{}, ErrRecoveryRestricted
	}
	seed, err := cryptox.DecodeRecoveryCode(completeCode)
	if err != nil {
		return RecoveryInfo{}, err
	}
	defer clear(seed)
	var challenge recoveryChallengeWire
	if err = w.request(ctx, w.accountPath("/recovery-challenges"), "", map[string]string{"accountGeneration": w.state.AccountGeneration}, &challenge); err != nil {
		return RecoveryInfo{}, err
	}
	created := w.now().Unix()
	if !positiveDecimal(challenge.RecoveryGeneration) || challenge.ExpiresAt <= created || challenge.ExpiresAt > created+125 {
		return RecoveryInfo{}, errors.New("recovery challenge expiry/generation invalid")
	}
	keys, err := cryptox.DeriveRecoveryKeys(seed, w.state.AccountID, w.state.AccountGeneration, challenge.RecoveryGeneration)
	if err != nil {
		return RecoveryInfo{}, err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	proof := cryptox.RecoveryProof{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, RecoveryGeneration: challenge.RecoveryGeneration, ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, ExpiresAt: strconv.FormatInt(challenge.ExpiresAt, 10)}
	raw, err := proof.SigningBytes()
	if err != nil {
		return RecoveryInfo{}, err
	}
	var expected []string
	_ = json.Unmarshal(raw, &expected)
	if !reflectStrings(expected, challenge.SigningPayload) {
		return RecoveryInfo{}, errors.New("recovery challenge exact purpose/account/nonce mismatch")
	}
	signature, err := cryptox.SignRecoveryProof(proof, keys.SigningPrivate)
	if err != nil {
		return RecoveryInfo{}, err
	}
	var session struct {
		Token            string `json:"token"`
		ExpiresAt        int64  `json:"expiresAt"`
		RotationRequired bool   `json:"rotationRequired"`
	}
	if err = w.request(ctx, w.accountPath("/recovery-sessions"), "", map[string]string{"accountGeneration": w.state.AccountGeneration, "challengeId": challenge.ChallengeID, "signature": signature}, &session); err != nil {
		return RecoveryInfo{}, err
	}
	if _, err = cryptox.DecodeBase64(session.Token, 32, 32); err != nil || !session.RotationRequired || session.ExpiresAt <= created || session.ExpiresAt > created+905 {
		return RecoveryInfo{}, errors.New("recovery session must be short-lived and restricted")
	}
	var vault recoveryVaultWire
	if err = w.request(ctx, w.accountPath("/recovery-vault?capability=issuer-origin-v1&envelopeEvidence=recovery-envelope-v1"), session.Token, nil, &vault); err != nil {
		return RecoveryInfo{}, recoveryVaultError(err)
	}
	envKeys, err := w.openRecoveryVault(vault, keys, challenge.RecoveryGeneration, nil, originsRequired)
	if err != nil {
		return RecoveryInfo{}, err
	}
	if !vault.RotationRequired {
		return RecoveryInfo{}, errors.New("new recovery session unexpectedly has management capability")
	}
	sessionHash := sha256.Sum256([]byte(session.Token))
	r := &recoveryRecord{OriginsRequired: originsRequired, SessionHash: hex.EncodeToString(sessionHash[:]), LastObservedAt: created, Version: 1, AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, CreatedAt: created, SessionToken: session.Token, SessionExpiresAt: session.ExpiresAt, RecoveryGeneration: challenge.RecoveryGeneration, SigningPublicKey: cryptox.EncodeBase64(keys.SigningPublic), ReceivingPublicKey: cryptox.EncodeBase64(keys.ReceivingPublic), Root: *vault.TrustRoot, Vault: vault, Keys: envKeys}
	w.state.Recovery = r
	w.login = nil
	if err = w.persist(); err != nil {
		w.clearRecovery()
		return RecoveryInfo{}, err
	}
	if len(capture) > 0 {
		if err := capture[0](keys.SigningPrivate); err != nil {
			return w.recoveryInfo(), err
		}
	}
	return w.recoveryInfo(), nil
}
func (w *Workflow) openRecoveryVault(v recoveryVaultWire, keys cryptox.RecoveryKeys, generation string, prior *cryptox.TrustRoot, originOption ...bool) (map[string]string, error) {
	if v.AccountID != w.state.AccountID || v.AccountGeneration != w.state.AccountGeneration || v.RecoveryGeneration != generation || v.RecoverySigningPublicKey != cryptox.EncodeBase64(keys.SigningPublic) || v.RecoveryReceivingPublicKey != cryptox.EncodeBase64(keys.ReceivingPublic) || v.TrustRoot == nil || cryptox.VerifyTrustRoot(v.AccountID, v.AccountGeneration, *v.TrustRoot, keys.SigningPublic) != nil {
		return nil, errors.New("recovered root is not pinned by the locally entered recovery code")
	}
	root := v.TrustRoot
	if root.RecoveryGeneration != generation || root.RecoverySigningPublicKey != v.RecoverySigningPublicKey || root.RecoveryReceivingPublicKey != v.RecoveryReceivingPublicKey || prior != nil && (root.RootDeviceID != prior.RootDeviceID || root.RootSigningPublicKey != prior.RootSigningPublicKey || root.RootReceivingPublicKey != prior.RootReceivingPublicKey) {
		return nil, errors.New("recovery cannot substitute root device")
	}
	originsRequired := w.state.Recovery != nil && w.state.Recovery.OriginsRequired
	if len(originOption) > 0 {
		originsRequired = originOption[0]
	}
	// Authenticate the exact ciphertext commitment before handling HPKE packets.
	if err := verifyRecoveryEnvelopes(v, *root, originsRequired); err != nil {
		return nil, err
	}
	envKeys := map[string]string{}
	for _, env := range v.Environments {
		if _, seen := envKeys[env.EnvironmentID]; seen {
			return nil, errors.New("duplicate recovery environment")
		}
		packet, err := cryptox.DecodeBase64(env.Envelope, 80, 80)
		if err != nil {
			return nil, err
		}
		key, err := cryptox.UnwrapEnvironmentKey(keys.ReceivingPrivate, cryptox.EnvelopeContext{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, EnvironmentID: env.EnvironmentID, KeyVersion: env.KeyVersion, RecipientType: "recovery", RecipientID: v.AccountID, RecipientGeneration: generation, RecipientPublicKey: v.RecoveryReceivingPublicKey}, packet)
		if err != nil {
			return nil, errors.New("recovery envelope authentication failed")
		}
		envKeys[env.EnvironmentID] = cryptox.EncodeBase64(key)
		clear(key)
	}
	if _, err := w.verifyRecoveryVault(v, *root, envKeys, originOption...); err != nil {
		return nil, err
	}
	return envKeys, nil
}
func (w *Workflow) verifyRecoveryGrant(s syncclient.SignedGrant, root cryptox.TrustRoot) error {
	g := s.Grant
	if g.AccountID != w.state.AccountID || g.AccountGeneration != w.state.AccountGeneration || g.IssuerDeviceID != root.RootDeviceID {
		return errors.Join(ErrRecoveryEvidence, errors.New("grant account or direct-root issuer mismatch"))
	}
	pub, err := cryptox.DecodeBase64(root.RootSigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyGrant(cryptox.SignedGrant{Grant: g, Signature: s.Signature}, pub) != nil {
		return errors.Join(ErrRecoveryEvidence, errors.New("direct-root grant signature invalid"))
	}
	if g.SubjectDeviceID == root.RootDeviceID && (g.SubjectSigningPublicKey != root.RootSigningPublicKey || g.SubjectReceivingPublicKey != root.RootReceivingPublicKey) {
		return ErrRecoveryEvidence
	}
	return nil
}

// Sequence metadata is not an initialization commitment: a server can relabel
// a later root-signed grant as sequence 1. Only the original initialization
// proposal and its two purpose-bound signatures authenticate genesis.
func (w *Workflow) recoveryGenesis(v recoveryVaultWire, root cryptox.TrustRoot) (map[string]syncclient.SignedGrant, map[string]bool, error) {
	i := v.OriginalInitialization
	if i == nil || i.Sequence != 1 || i.Sequence > v.Sequence || i.Proof.AccountID != v.AccountID || i.Proof.AccountGeneration != v.AccountGeneration || i.Proposal.Device.ID != root.RootDeviceID || i.Proposal.Device.SigningPublicKey != root.RootSigningPublicKey || i.Proposal.Device.ReceivingPublicKey != root.RootReceivingPublicKey {
		return nil, nil, ErrRecoveryEvidence
	}
	hash, err := i.Proposal.Hash(v.AccountID, v.AccountGeneration)
	if err != nil || hash != i.Proof.ProposalHash {
		return nil, nil, ErrRecoveryEvidence
	}
	deviceKey, err := cryptox.DecodeBase64(root.RootSigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyInitializationProof(i.Proof, i.DeviceSignature, deviceKey) != nil {
		return nil, nil, ErrRecoveryEvidence
	}
	// Proposal.Hash validates the original recovery-signed manifest and every
	// initial device grant. The device proof above independently binds these old
	// recovery keys; never compare them to the newly rotated current keys.
	originalRecoveryKey, err := cryptox.DecodeBase64(i.Proposal.RecoverySigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyInitializationProof(i.Proof, i.RecoverySignature, originalRecoveryKey) != nil {
		return nil, nil, ErrRecoveryEvidence
	}
	genesis := map[string]syncclient.SignedGrant{}
	initialHashes := map[string]bool{}
	for _, env := range i.Proposal.Environments {
		g := syncclient.SignedGrant{Grant: env.Grant.Grant, Signature: env.Grant.Signature}
		h, err := cryptox.IssuerAuthorityHash(env.Grant)
		if err != nil || initialHashes[h] {
			return nil, nil, ErrRecoveryEvidence
		}
		genesis[env.EnvironmentID] = g
		initialHashes[h] = true
	}
	if len(genesis) == 0 || len(genesis) != len(v.Environments) {
		return nil, nil, ErrRecoveryEvidence
	}
	for _, env := range v.Environments {
		if env.KeyVersion != "1" || genesis[env.EnvironmentID].Signature == "" {
			return nil, nil, ErrRecoveryEvidence
		}
	}
	accepted := map[string]bool{}
	initialSeen := 0
	last := uint64(0)
	for _, e := range v.GrantHistory {
		if e.Sequence == 0 || e.Sequence < last || e.Sequence > v.Sequence {
			return nil, nil, ErrRecoveryEvidence
		}
		last = e.Sequence
		if _, ok := genesis[e.Grant.Grant.EnvironmentID]; !ok || e.Grant.Grant.KeyVersion != "1" {
			return nil, nil, ErrRecoveryEvidence
		}
		if err := w.verifyRecoveryGrant(e.Grant, root); err != nil {
			return nil, nil, err
		}
		h, err := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: e.Grant.Grant, Signature: e.Grant.Signature})
		if err != nil || accepted[h] {
			return nil, nil, ErrRecoveryEvidence
		}
		if e.Sequence == i.Sequence {
			if e.Authorization != nil || !initialHashes[h] {
				return nil, nil, ErrRecoveryEvidence
			}
			initialSeen++
		} else {
			if e.Authorization == nil {
				return nil, nil, ErrRecoveryEvidence
			}
			a := e.Authorization.Grant
			if err := w.verifyRecoveryGrant(*e.Authorization, root); err != nil {
				return nil, nil, err
			}
			source, err := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: a, Signature: e.Authorization.Signature})
			if err != nil || !accepted[source] || a.Role != "admin" || a.SubjectDeviceID != e.Grant.Grant.IssuerDeviceID || a.EnvironmentID != e.Grant.Grant.EnvironmentID || a.KeyVersion != "1" {
				return nil, nil, ErrRecoveryEvidence
			}
		}
		accepted[h] = true
	}
	if initialSeen != len(initialHashes) {
		return nil, nil, ErrRecoveryEvidence
	}
	return genesis, accepted, nil
}

// Bound every candidate before the explicit origins entry parses it. The legacy
// initial-only entry never uses this candidate to add an issuer or genesis grant.
func validateRecoveryEvidenceCandidate(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > 1<<20 || !json.Valid(raw) {
		return ErrRecoveryEvidence
	}
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ErrRecoveryEvidence
	}
	d := json.NewDecoder(bytes.NewReader(trimmed))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 64 {
			return ErrRecoveryEvidence
		}
		token, err := d.Token()
		if err != nil {
			return ErrRecoveryEvidence
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				name, valid := key.(string)
				if err != nil || !valid || seen[name] {
					return ErrRecoveryEvidence
				}
				seen[name] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	return visit(0)
}

// The origin entry authenticates historical issuers from the committed genesis;
// the compatibility entry remains strict initial-only. Neither trusts publicDevices.
func (w *Workflow) verifyRecoveryVault(v recoveryVaultWire, root cryptox.TrustRoot, keys map[string]string, originOption ...bool) ([]RecoveredEnvironment, error) {
	if err := validateRecoveryEvidenceCandidate(v.IssuerEvidence); err != nil {
		return nil, err
	}
	if v.AccountID != w.state.AccountID || v.AccountGeneration != w.state.AccountGeneration || v.Sequence == 0 || v.Sequence > 9007199254740991 || len(v.Environments) == 0 || len(v.Environments) > 256 || len(v.Environments) != len(keys) || v.TrustRoot == nil || *v.TrustRoot != root || root.RecoveryGeneration != v.RecoveryGeneration || root.RecoverySigningPublicKey != v.RecoverySigningPublicKey || root.RecoveryReceivingPublicKey != v.RecoveryReceivingPublicKey {
		return nil, errors.New("recovery snapshot account/sequence/root invalid")
	}
	originsRequired := w.state.Recovery != nil && w.state.Recovery.OriginsRequired
	if len(originOption) > 0 {
		originsRequired = originOption[0]
	}
	var acceptedGrants map[string]bool
	var err error
	if originsRequired {
		acceptedGrants, err = w.verifyRecoveryOriginGrants(v, root)
	} else {
		_, acceptedGrants, err = w.recoveryGenesis(v, root)
	}
	if err != nil {
		return nil, err
	}
	if err := verifyRecoveryEnvelopes(v, root, originsRequired); err != nil {
		return nil, err
	}
	return w.verifyRecoveryVaultData(v, root, keys, originsRequired, acceptedGrants)
}

// Both recovery profiles authenticate their own envelope commitments before
// this shared signed mutation/AEAD projection. No caller can mark a device trusted.
func (w *Workflow) verifyRecoveryVaultData(v recoveryVaultWire, root cryptox.TrustRoot, keys map[string]string, originsRequired bool, acceptedGrants map[string]bool) ([]RecoveredEnvironment, error) {
	envs := map[string]*RecoveredEnvironment{}
	for _, env := range v.Environments {
		if !identifier.MatchString(env.EnvironmentID) || !positiveDecimal(env.KeyVersion) || envs[env.EnvironmentID] != nil {
			return nil, errors.New("recovery environment/version invalid")
		}
		if _, err := cryptox.DecodeBase64(env.Envelope, 80, 80); err != nil {
			return nil, err
		}
		if _, err := cryptox.DecodeBase64(keys[env.EnvironmentID], 32, 32); err != nil {
			return nil, err
		}
		envs[env.EnvironmentID] = &RecoveredEnvironment{ID: env.EnvironmentID, KeyVersion: env.KeyVersion, Variables: map[string]string{}}
	}
	for _, g := range v.CurrentGrants {
		if originsRequired {
			e := envs[g.Grant.EnvironmentID]
			if e == nil || g.Grant.KeyVersion != e.KeyVersion || g.Grant.Role == "none" {
				continue
			}
		}
		h, err := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature})
		if err != nil || !acceptedGrants[h] {
			return nil, ErrRecoveryEvidence
		}
	}
	seen := map[uint64]bool{}
	for _, event := range v.GrantHistory {
		seen[event.Sequence] = true
	}

	last := uint64(0)
	for _, event := range v.Events {
		m := event.Mutation.Mutation
		env := envs[m.EnvironmentID]
		if event.Sequence <= last || event.Sequence > v.Sequence || seen[event.Sequence] || env == nil || event.Authorization == nil {
			return nil, errors.New("recovery mutation sequence/environment/authorization invalid")
		}
		seen[event.Sequence] = true
		last = event.Sequence
		if !originsRequired {
			if err := w.verifyRecoveryGrant(*event.Authorization, root); err != nil {
				return nil, err
			}
		}
		g := event.Authorization.Grant
		h, err := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: g, Signature: event.Authorization.Signature})
		if err != nil || !acceptedGrants[h] {
			return nil, ErrRecoveryEvidence
		}
		if m.AccountID != v.AccountID || m.AccountGeneration != v.AccountGeneration || m.KeyVersion != env.KeyVersion || g.EnvironmentID != m.EnvironmentID || g.KeyVersion != m.KeyVersion || g.GrantGeneration != m.GrantGeneration || g.SubjectDeviceID != m.DeviceID || g.Role != "rw" && g.Role != "admin" {
			return nil, errors.Join(ErrRecoveryEvidence, errors.New("mutation exact historical authorization mismatch"))
		}
		pub, err := cryptox.DecodeBase64(g.SubjectSigningPublicKey, 32, 32)
		if err != nil || cryptox.VerifyMutation(cryptox.SignedMutation{Mutation: m, Signature: event.Mutation.Signature}, pub) != nil {
			return nil, errors.Join(ErrRecoveryEvidence, errors.New("mutation device signature invalid"))
		}
		if m.Operation == "delete" {
			delete(env.Variables, m.Name)
			continue
		}
		key, err := cryptox.DecodeBase64(keys[m.EnvironmentID], 32, 32)
		if err != nil {
			return nil, err
		}
		packet, err := cryptox.DecodeBase64(m.Payload, 40, 65576)
		if err != nil {
			clear(key)
			return nil, err
		}
		plain, err := cryptox.DecryptValue(key, cryptox.ValueContext{AccountID: m.AccountID, AccountGeneration: m.AccountGeneration, EnvironmentID: m.EnvironmentID, KeyVersion: m.KeyVersion, Name: m.Name}, packet)
		clear(key)
		if err != nil || !utf8.Valid(plain) {
			clear(plain)
			return nil, errors.New("recovery data authentication failed")
		}
		env.Variables[m.Name] = string(plain)
		clear(plain)
	}
	ids := make([]string, 0, len(envs))
	for id := range envs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]RecoveredEnvironment, 0, len(ids))
	for _, id := range ids {
		out = append(out, *envs[id])
	}
	return out, nil
}
func (w *Workflow) RecoveryView() (RecoveryView, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.RecoveryAuthority != nil {
		return w.authorityRecoveryViewLocked()
	}
	if err := w.recoveryLive(); err != nil {
		return RecoveryView{}, err
	}
	r := w.state.Recovery
	if r.Rotation != nil && !r.RotationCompleted {
		return RecoveryView{}, ErrRecoveryPending
	}
	envs, err := w.verifyRecoveryVault(r.Vault, r.Root, r.Keys)
	if err != nil {
		return RecoveryView{}, err
	}
	return RecoveryView{Info: w.recoveryInfo(), Environments: envs}, nil
}

// A received invalidation removes restricted plaintext and bearer immediately.
// It still cannot prove that an uncertain rotation id was accepted.
func (w *Workflow) recoveryRequest(ctx context.Context, path string, body any, out any) error {
	r := w.state.Recovery
	if r == nil {
		return ErrRecoveryRestricted
	}
	err := w.request(ctx, path, r.SessionToken, body, out)
	var rejected *syncclient.RequestError
	if errors.As(err, &rejected) && (rejected.Status == 401 || rejected.Status == 403 && rejected.Code == "recovery_session_stale") {
		cleanup := w.engine.Logout()
		cleanup = errors.Join(cleanup, w.invalidateTrust())
		return errors.Join(syncclient.ErrTrustInvalidated, err, cleanup)
	}
	return err
}
func sameRecoveryInitialization(a, b *recoveryOriginalInitialization) bool {
	return a != nil && b != nil && a.Proof == b.Proof && a.DeviceSignature == b.DeviceSignature && a.RecoverySignature == b.RecoverySignature && a.Sequence == b.Sequence
}
func (w *Workflow) refreshRecoveryVault(ctx context.Context) error {
	r := w.state.Recovery
	var v recoveryVaultWire
	if err := w.recoveryRequest(ctx, w.accountPath("/recovery-vault?capability=issuer-origin-v1&envelopeEvidence=recovery-envelope-v1"), nil, &v); err != nil {
		return recoveryVaultError(err)
	}
	if v.Sequence < r.Vault.Sequence || v.RecoveryGeneration != r.RecoveryGeneration || v.RotationRequired != !r.RotationCompleted || !sameRecoveryInitialization(v.OriginalInitialization, r.Vault.OriginalInitialization) {
		return errors.New("recovery checkpoint or capability rollback")
	}
	if _, err := w.verifyRecoveryVault(v, r.Root, r.Keys); err != nil {
		return err
	}
	// Missing/new/rotated environment keys must never be silently fabricated.
	for _, e := range v.Environments {
		found := false
		for _, old := range r.Vault.Environments {
			if e.EnvironmentID == old.EnvironmentID && e.KeyVersion == old.KeyVersion && e.Envelope == old.Envelope {
				found = true
				break
			}
		}
		if !found {
			return errors.New("recovery environment changed; re-enter code in a new explicit recovery context")
		}
	}
	r.Vault = v
	return w.persist()
}
func (w *Workflow) BeginRecoveryRotation(ctx context.Context, id string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.RecoveryAuthority != nil {
		return "", ErrRecoveryRestricted
	}
	if err := w.recoveryLive(); err != nil {
		return "", err
	}
	r := w.state.Recovery
	if r.Rotation != nil || r.RotationCompleted {
		return "", ErrRecoveryPending
	}
	if len(id) > 64 || !identifier.MatchString(id) {
		return "", errors.New("recovery rotation id invalid")
	}
	if err := w.refreshRecoveryVault(ctx); err != nil {
		return "", err
	}
	old, err := strconv.ParseUint(r.RecoveryGeneration, 10, 64)
	if err != nil || old == ^uint64(0) {
		return "", errors.New("recovery generation exhausted")
	}
	generation := strconv.FormatUint(old+1, 10)
	seed, err := cryptox.GenerateRecoverySeed()
	if err != nil {
		return "", err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, generation)
	if err != nil {
		return "", err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	root := r.Root
	root.RecoveryGeneration = generation
	root.RecoverySigningPublicKey = cryptox.EncodeBase64(keys.SigningPublic)
	root.RecoveryReceivingPublicKey = cryptox.EncodeBase64(keys.ReceivingPublic)
	root, err = cryptox.SignTrustRoot(r.AccountID, r.AccountGeneration, root, keys.SigningPrivate)
	if err != nil {
		return "", err
	}
	envelopes := make([]cryptox.RecoveryEnvelope, 0, len(r.Vault.Environments))
	for _, e := range r.Vault.Environments {
		key, err := cryptox.DecodeBase64(r.Keys[e.EnvironmentID], 32, 32)
		if err != nil {
			return "", err
		}
		packet, err := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion, RecipientType: "recovery", RecipientID: r.AccountID, RecipientGeneration: generation, RecipientPublicKey: root.RecoveryReceivingPublicKey})
		clear(key)
		if err != nil {
			return "", err
		}
		envelopes = append(envelopes, cryptox.RecoveryEnvelope{EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion, Envelope: cryptox.EncodeBase64(packet)})
	}
	sort.Slice(envelopes, func(i, j int) bool { return envelopes[i].EnvironmentID < envelopes[j].EnvironmentID })
	r.Rotation = &recoveryRotationRecord{PriorRoot: r.Root, Proposal: cryptox.RecoveryRotationProposal{IdempotencyKey: id, NewRecoveryGeneration: generation, NewRecoverySigningPublicKey: root.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, Envelopes: envelopes, NewTrustRoot: root}, CreatedAt: w.now().Unix(), BaseSequence: r.Vault.Sequence}
	if err = w.persist(); err != nil {
		r.Rotation = nil
		return "", err
	}
	code, err := cryptox.EncodeRecoveryCode(seed)
	if err != nil {
		return "", err
	}
	var status recoveryRotationWire
	if err = w.recoveryRequest(ctx, w.accountPath("/recovery-rotations"), r.Rotation.Proposal, &status); err != nil {
		return code, errors.Join(ErrRecoveryPending, err)
	}
	if _, err = w.rotationProof(r.Rotation, status); err != nil {
		return code, err
	}
	if status.State != "pending" {
		return code, errors.New("new recovery rotation unexpectedly not pending")
	}
	r.Rotation.Challenge = &status
	if err = w.persist(); err != nil {
		return code, errors.Join(ErrRecoveryPending, err)
	}
	if w.recoverySession != nil {
		if err := w.bindRecoverySessionRotation(w.recoverySession); err != nil {
			return code, err
		}
	}
	return code, nil
}
func (w *Workflow) rotationProof(q *recoveryRotationRecord, s recoveryRotationWire) (cryptox.RecoveryRotationProof, error) {
	r := w.state.Recovery
	if s.IdempotencyKey != q.Proposal.IdempotencyKey || s.State != "pending" && s.State != "complete" && s.State != "expired" && s.State != "superseded" || s.ExpiresAt <= q.CreatedAt || s.ExpiresAt > q.CreatedAt+125 || s.RecoveryGeneration != q.PriorRoot.RecoveryGeneration || s.NewRecoveryGeneration != q.Proposal.NewRecoveryGeneration {
		return cryptox.RecoveryRotationProof{}, errors.New("rotation response exact id/generation/expiry mismatch")
	}
	proof, err := cryptox.NewRecoveryRotationProof(r.AccountID, r.AccountGeneration, r.SessionToken, s.ChallengeID, s.Nonce, strconv.FormatInt(s.ExpiresAt, 10), q.Proposal, q.PriorRoot)
	if err != nil {
		return proof, err
	}
	proof.SessionHash = r.SessionHash
	raw, err := proof.SigningBytes()
	if err != nil {
		return proof, err
	}
	var expected []string
	_ = json.Unmarshal(raw, &expected)
	if s.TrustRootHash == nil || *s.TrustRootHash != proof.TrustRootHash || s.EnvelopesHash != proof.EnvelopesHash || !reflectStrings(expected, s.SigningPayload) {
		return proof, errors.New("rotation response nonce/session/full envelopes/root mismatch")
	}
	if s.State == "complete" {
		if s.Sequence == nil || *s.Sequence <= q.BaseSequence || *s.Sequence > 9007199254740991 {
			return proof, errors.New("rotation completion sequence invalid")
		}
	} else if s.Sequence != nil {
		return proof, errors.New("pending rotation cannot claim completion sequence")
	}
	if q.Challenge != nil && (q.Challenge.ChallengeID != s.ChallengeID || q.Challenge.Nonce != s.Nonce || q.Challenge.ExpiresAt != s.ExpiresAt || !reflectStrings(q.Challenge.SigningPayload, s.SigningPayload)) {
		return proof, errors.New("rotation original challenge changed")
	}
	return proof, nil
}
func (w *Workflow) queryRecoveryRotation(ctx context.Context) (recoveryRotationWire, error) {
	r := w.state.Recovery
	q := r.Rotation
	var s recoveryRotationWire
	err := w.recoveryRequest(ctx, w.accountPath("/recovery-rotations/"+q.Proposal.IdempotencyKey), nil, &s)
	if err != nil {
		return s, err
	}
	if s.State == "absent" {
		if s.IdempotencyKey != q.Proposal.IdempotencyKey || s.ChallengeID != "" || s.Sequence != nil || q.Challenge != nil || s.Nonce != "" || s.ExpiresAt != 0 || s.RecoveryGeneration != "" || s.NewRecoveryGeneration != "" || s.EnvelopesHash != "" || s.TrustRootHash != nil || len(s.SigningPayload) != 0 || s.Replayed {
			return s, errors.New("recovery original rotation disappeared")
		}
		return s, nil
	}
	if _, err = w.rotationProof(q, s); err != nil {
		return s, err
	}
	return s, nil
}

// CompleteRecoveryRotation needs the full new code again on every explicit resume.
// No saved seed is used to manufacture proof of re-entry.
func (w *Workflow) CompleteRecoveryRotation(ctx context.Context, completeNewCode string) (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.RecoveryAuthority != nil {
		return w.recoveryInfo(), ErrRecoveryRestricted
	}
	if err := w.recoveryLive(); err != nil {
		return w.recoveryInfo(), err
	}
	r := w.state.Recovery
	q := r.Rotation
	if q == nil {
		return w.recoveryInfo(), ErrRecoveryPending
	}
	seed, err := cryptox.DecodeRecoveryCode(completeNewCode)
	if err != nil {
		return w.recoveryInfo(), err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, q.Proposal.NewRecoveryGeneration)
	if err != nil {
		return w.recoveryInfo(), err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	if cryptox.EncodeBase64(keys.SigningPublic) != q.Proposal.NewRecoverySigningPublicKey || cryptox.EncodeBase64(keys.ReceivingPublic) != q.Proposal.NewRecoveryReceivingPublicKey {
		return w.recoveryInfo(), errors.New("complete new recovery code does not match proposal")
	}
	if r.RotationCompleted {
		return w.recoveryInfo(), nil
	}
	if err = w.persist(); err != nil {
		return w.recoveryInfo(), err
	}
	s, err := w.queryRecoveryRotation(ctx)
	if err != nil {
		return w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
	}
	if s.State == "absent" {
		if w.now().Unix() < q.CreatedAt-5 || w.now().Unix() >= q.CreatedAt+120 {
			return w.recoveryInfo(), ErrRecoveryExpired
		}
		if err = w.recoveryRequest(ctx, w.accountPath("/recovery-rotations"), q.Proposal, &s); err != nil {
			return w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
		}
		if _, err = w.rotationProof(q, s); err != nil {
			return w.recoveryInfo(), err
		}
	}
	if s.State == "expired" || s.State == "superseded" {
		return w.recoveryInfo(), ErrRecoveryExpired
	}
	if q.Challenge == nil {
		q.Challenge = &s
	}
	proof, err := w.rotationProof(q, s)
	if err != nil {
		return w.recoveryInfo(), err
	}
	signature, err := cryptox.SignRecoveryRotationProof(proof, keys.SigningPrivate)
	if err != nil {
		return w.recoveryInfo(), err
	}
	if q.Signature != "" && q.Signature != signature {
		return w.recoveryInfo(), errors.New("recovery original proof signature changed")
	}
	q.Signature = signature
	if err = w.persist(); err != nil {
		return w.recoveryInfo(), err
	}
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	if s.State != "complete" {
		if q.DeadlineClosed || s.ExpiresAt <= w.now().Unix() || w.now().Unix() < q.CreatedAt-5 {
			return w.recoveryInfo(), ErrRecoveryExpired
		}
		if err = w.recoveryRequest(ctx, w.accountPath("/recovery-rotations/"+q.Proposal.IdempotencyKey+"/complete"), map[string]string{"challengeId": s.ChallengeID, "signature": signature}, &s); err != nil {
			return w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
		}
		if _, err = w.rotationProof(q, s); err != nil {
			return w.recoveryInfo(), err
		}
		if s.State != "complete" {
			return w.recoveryInfo(), ErrRecoveryPending
		}
	}
	// Receipt alone is insufficient: fetch the same restricted vault, validate every
	// signature and unwrap all newly installed recovery envelopes using re-entered keys.
	var v recoveryVaultWire
	if err = w.recoveryRequest(ctx, w.accountPath("/recovery-vault?capability=issuer-origin-v1&envelopeEvidence=recovery-envelope-v1"), nil, &v); err != nil {
		return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, recoveryVaultError(err))
	}
	if v.Sequence < *s.Sequence || v.RotationRequired || len(v.Environments) != len(q.Proposal.Envelopes) || !sameRecoveryInitialization(v.OriginalInitialization, r.Vault.OriginalInitialization) {
		return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, errors.New("new recovery capability or full envelope set not applied"))
	}
	for _, e := range q.Proposal.Envelopes {
		matched := false
		for _, current := range v.Environments {
			if current == e {
				matched = true
				break
			}
		}
		if !matched {
			return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, errors.New("accepted recovery envelope differs from original proposal"))
		}
	}
	newkeys, err := w.openRecoveryVault(v, keys, q.Proposal.NewRecoveryGeneration, &r.Root)
	if err != nil {
		return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	for env, key := range newkeys {
		if key != r.Keys[env] {
			return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, errors.New("rotation changed environment data key"))
		}
	}
	before := clone(r)
	q.AcceptedSequence = *s.Sequence
	r.RecoveryGeneration = v.RecoveryGeneration
	r.SigningPublicKey = v.RecoverySigningPublicKey
	r.ReceivingPublicKey = v.RecoveryReceivingPublicKey
	r.Root = *v.TrustRoot
	r.Keys = newkeys
	r.Vault = v
	r.RotationCompleted = true
	if err = w.persist(); err != nil {
		w.state.Recovery = before
		return w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return w.recoveryInfo(), nil
}

// QueryRecoveryRotation only reports a checked receipt; it does not bypass full code
// re-entry or the post-acceptance HPKE/data verification in CompleteRecoveryRotation.
func (w *Workflow) QueryRecoveryRotation(ctx context.Context) (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.RecoveryAuthority != nil {
		return w.recoveryInfo(), ErrRecoveryRestricted
	}
	if err := w.recoveryLive(); err != nil {
		return w.recoveryInfo(), err
	}
	if w.state.Recovery.Rotation == nil {
		return w.recoveryInfo(), ErrRecoveryPending
	}
	s, err := w.queryRecoveryRotation(ctx)
	if err != nil {
		return w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
	}
	info := w.recoveryInfo()
	if s.State == "complete" && !w.state.Recovery.RotationCompleted {
		info.State = "accepted-unverified"
		info.Sequence = *s.Sequence
	}
	return info, nil
}
func (w *Workflow) clearRecovery() {
	w.state.RecoveryAuthority = nil
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	if r := w.state.Recovery; r != nil {
		r.SessionToken = ""
		for id := range r.Keys {
			delete(r.Keys, id)
		}
		r.Vault = recoveryVaultWire{}
	}
	w.state.Recovery = nil
}
