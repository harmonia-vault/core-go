package mobileworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

const recoveryAuthorityVaultPath = "/recovery-vault?capability=issuer-recovery-v1&envelopeEvidence=recovery-envelope-v1"

func recoveryAuthorityPath(operation string) string {
	return "/" + operation + "?capability=issuer-recovery-v1"
}

// BeginRecoveryAuthoritySession is the explicit continuous-authority entry. A
// current code plus a gap in the original continuity chain never falls back.
func (w *Workflow) BeginRecoveryAuthoritySession(ctx context.Context, completeOldCode string) (*RecoverySession, RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryOnly(); err != nil {
		return nil, RecoveryInfo{}, err
	}
	if w.state.Recovery != nil || w.login == nil || w.login.AccountID != w.state.AccountID || w.login.AccountGeneration != w.state.AccountGeneration || w.login.ExpiresAt <= w.now().Unix() {
		return nil, RecoveryInfo{}, ErrRecoveryRestricted
	}
	seed, err := cryptox.DecodeRecoveryCode(completeOldCode)
	if err != nil {
		return nil, RecoveryInfo{}, err
	}
	defer clear(seed)
	var challenge recoveryChallengeWire
	if err = w.request(ctx, w.accountPath("/recovery-challenges"), "", map[string]string{"accountGeneration": w.state.AccountGeneration}, &challenge); err != nil {
		return nil, RecoveryInfo{}, err
	}
	created := w.now().Unix()
	if !positiveDecimal(challenge.RecoveryGeneration) || challenge.ExpiresAt <= created || challenge.ExpiresAt > created+125 {
		return nil, RecoveryInfo{}, ErrRecoveryEvidence
	}
	keys, err := cryptox.DeriveRecoveryKeys(seed, w.state.AccountID, w.state.AccountGeneration, challenge.RecoveryGeneration)
	if err != nil {
		return nil, RecoveryInfo{}, err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	proof := cryptox.RecoveryProof{AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, RecoveryGeneration: challenge.RecoveryGeneration, ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, ExpiresAt: strconv.FormatInt(challenge.ExpiresAt, 10)}
	canonical, err := proof.SigningBytes()
	if err != nil {
		return nil, RecoveryInfo{}, err
	}
	if !reflectStrings(decodeStrings(canonical), challenge.SigningPayload) {
		return nil, RecoveryInfo{}, ErrRecoveryEvidence
	}
	signature, err := cryptox.SignRecoveryProof(proof, keys.SigningPrivate)
	if err != nil {
		return nil, RecoveryInfo{}, err
	}
	var session struct {
		Token            string `json:"token"`
		ExpiresAt        int64  `json:"expiresAt"`
		RotationRequired bool   `json:"rotationRequired"`
	}
	if err = w.request(ctx, w.accountPath("/recovery-sessions"), "", map[string]string{"accountGeneration": w.state.AccountGeneration, "challengeId": challenge.ChallengeID, "signature": signature}, &session); err != nil {
		return nil, RecoveryInfo{}, err
	}
	if _, err = cryptox.DecodeBase64(session.Token, 32, 32); err != nil || !session.RotationRequired || session.ExpiresAt <= created || session.ExpiresAt > created+905 {
		return nil, RecoveryInfo{}, ErrRecoveryEvidence
	}
	var vault recoveryAuthorityVault
	if err = w.request(ctx, w.accountPath(recoveryAuthorityVaultPath), session.Token, nil, &vault); err != nil {
		return nil, RecoveryInfo{}, recoveryVaultError(err)
	}
	envKeys, err := w.openAuthorityVault(vault, keys, nil)
	if err != nil {
		return nil, RecoveryInfo{}, err
	}
	if !vault.RotationRequired {
		return nil, RecoveryInfo{}, ErrRecoveryEvidence
	}
	hash := sha256.Sum256([]byte(session.Token))
	r := &recoveryRecord{Version: 1, OriginsRequired: true, AccountID: w.state.AccountID, AccountGeneration: w.state.AccountGeneration, CreatedAt: created, LastObservedAt: created, SessionToken: session.Token, SessionHash: hex.EncodeToString(hash[:]), SessionExpiresAt: session.ExpiresAt, RecoveryGeneration: vault.RecoveryGeneration, SigningPublicKey: vault.RecoverySigningPublicKey, ReceivingPublicKey: vault.RecoveryReceivingPublicKey, Root: *vault.TrustRoot, Vault: vault.recoveryVaultWire, Keys: envKeys}
	w.state.Recovery = r
	w.state.RecoveryAuthority = &recoveryAuthorityRecord{Version: 1, Vault: vault}
	w.login = nil
	if err = w.persist(); err != nil {
		w.clearRecovery()
		return nil, RecoveryInfo{}, err
	}
	owner, err := w.newRecoverySession(keys.SigningPrivate)
	if err != nil {
		return nil, w.recoveryAuthorityInfo(), err
	}
	w.recoverySession = owner
	return owner, w.recoveryAuthorityInfo(), nil
}

func (w *Workflow) openAuthorityVault(v recoveryAuthorityVault, keys cryptox.RecoveryKeys, prior *cryptox.TrustRoot) (map[string]string, error) {
	if v.AccountID != w.state.AccountID || v.AccountGeneration != w.state.AccountGeneration || v.TrustRoot == nil || v.RecoverySigningPublicKey != cryptox.EncodeBase64(keys.SigningPublic) || v.RecoveryReceivingPublicKey != cryptox.EncodeBase64(keys.ReceivingPublic) || cryptox.VerifyTrustRoot(v.AccountID, v.AccountGeneration, *v.TrustRoot, keys.SigningPublic) != nil {
		return nil, ErrRecoveryEvidence
	}
	root := v.TrustRoot
	if prior != nil && (root.RootDeviceID != prior.RootDeviceID || root.RootSigningPublicKey != prior.RootSigningPublicKey || root.RootReceivingPublicKey != prior.RootReceivingPublicKey) {
		return nil, ErrRecoveryEvidence
	}
	if _, err := verifyAuthorityEnvelopeCommitments(v); err != nil {
		return nil, err
	}
	if _, err := w.verifyRecoveryOriginGrants(v.recoveryVaultWire, *root); err != nil {
		return nil, err
	}
	envKeys := map[string]string{}
	for _, e := range v.Environments {
		if _, duplicate := envKeys[e.EnvironmentID]; duplicate {
			return nil, ErrRecoveryEvidence
		}
		packet, err := cryptox.DecodeBase64(e.Envelope, 80, 80)
		if err != nil {
			return nil, err
		}
		key, err := cryptox.UnwrapEnvironmentKey(keys.ReceivingPrivate, cryptox.EnvelopeContext{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion, RecipientType: "recovery", RecipientID: v.AccountID, RecipientGeneration: v.RecoveryGeneration, RecipientPublicKey: v.RecoveryReceivingPublicKey}, packet)
		if err != nil {
			return nil, ErrRecoveryEvidence
		}
		envKeys[e.EnvironmentID] = cryptox.EncodeBase64(key)
		clear(key)
	}
	if _, err := w.verifyAuthorityVault(v, *root, envKeys); err != nil {
		return nil, err
	}
	return envKeys, nil
}
func (w *Workflow) recoveryAuthorityInfo() RecoveryInfo {
	r, a := w.state.Recovery, w.state.RecoveryAuthority
	if r == nil || a == nil {
		return RecoveryInfo{State: "none"}
	}
	info := RecoveryInfo{State: "restricted", TrustedDevice: false, RotationRequired: r.Vault.RotationRequired, RecoveryGeneration: r.RecoveryGeneration, Sequence: r.Vault.Sequence, Environments: len(r.Vault.Environments), ExpiresAt: r.SessionExpiresAt}
	if r.SessionClosed {
		info.State = "expired"
	}
	if p := a.Pending; p != nil {
		info.ID = p.Packet.Transition.OperationID
		if r.SessionClosed {
			info.State = "expired-pending"
		} else if p.Applied {
			info.State = "rotation-complete-restricted"
		} else if p.AcceptedSequence != 0 {
			info.State = "accepted-unverified"
		} else {
			info.State = "pending-new-code"
		}
	}
	return info
}
func (w *Workflow) authoritySessionLive() error {
	if err := w.recoveryLive(); err != nil {
		return err
	}
	if w.state.RecoveryAuthority == nil || w.recoverySession == nil {
		return ErrRecoverySession
	}
	return w.bindRecoverySessionRotation(w.recoverySession)
}
func (w *Workflow) authorityRecoveryViewLocked() (RecoveryView, error) {
	if err := w.authoritySessionLive(); err != nil {
		return RecoveryView{}, err
	}
	if w.recoveredDevicePending() {
		return RecoveryView{}, ErrRecoveryPending
	}
	if p := w.state.RecoveryAuthority.Pending; p != nil && !p.Applied {
		return RecoveryView{}, ErrRecoveryPending
	}
	envs, err := w.verifyAuthorityVault(w.state.RecoveryAuthority.Vault, w.state.Recovery.Root, w.state.Recovery.Keys)
	if err != nil {
		return RecoveryView{}, err
	}
	return RecoveryView{Info: w.recoveryAuthorityInfo(), Environments: envs}, nil
}
func decodeStrings(b []byte) []string {
	var out []string
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// ResumeRecoveryAuthoritySession rebuilds only the original restricted context
// after interruption, using complete-code reentry. A sealed signed transition
// no longer needs or permits resurrection of its old signing owner.
func (w *Workflow) ResumeRecoveryAuthoritySession(ctx context.Context, completeCode string) (*RecoverySession, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryLive(); err != nil {
		return nil, err
	}
	a, r := w.state.RecoveryAuthority, w.state.Recovery
	if a == nil {
		return nil, ErrRecoveryRestricted
	}
	if p := a.Pending; p != nil && !p.Applied && p.Packet.AuthorizationSignature != "" {
		return nil, ErrRecoveryPending
	}
	if err := w.refreshAuthorityVault(ctx); err != nil {
		return nil, err
	}
	seed, err := cryptox.DecodeRecoveryCode(completeCode)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, r.RecoveryGeneration)
	if err != nil {
		return nil, err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	if cryptox.EncodeBase64(keys.SigningPublic) != r.SigningPublicKey || cryptox.EncodeBase64(keys.ReceivingPublic) != r.ReceivingPublicKey {
		return nil, ErrRecoverySession
	}
	if w.recoverySession != nil {
		w.recoverySession.Close()
		w.recoverySession = nil
	}
	owner, err := w.newRecoverySession(keys.SigningPrivate)
	if err != nil {
		return nil, err
	}
	w.recoverySession = owner
	return owner, nil
}
