package mobileworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

// refreshAuthorityVault never creates keys for a concurrently added or rotated
// environment. Such a change requires an explicit full-code recovery restart.
func (w *Workflow) refreshAuthorityVault(ctx context.Context) error {
	r, a := w.state.Recovery, w.state.RecoveryAuthority
	var v recoveryAuthorityVault
	if err := w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityVaultPath), nil, &v); err != nil {
		return recoveryVaultError(err)
	}
	if v.Sequence < a.Vault.Sequence || !sameJSONValue(v.Transitions, a.Vault.Transitions) || !sameJSONValue(v.OriginalInitialization, a.Vault.OriginalInitialization) || !sameJSONValue(v.Environments, a.Vault.Environments) || v.RecoveryGeneration != r.RecoveryGeneration || v.TrustRoot == nil || *v.TrustRoot != r.Root || v.RotationRequired != a.Vault.RotationRequired {
		return ErrRecoveryEvidence
	}
	if _, err := w.verifyAuthorityVault(v, r.Root, r.Keys); err != nil {
		return err
	}
	before := clone(a.Vault)
	a.Vault = v
	r.Vault = v.recoveryVaultWire
	if err := w.persist(); err != nil {
		a.Vault = before
		r.Vault = before.recoveryVaultWire
		return err
	}
	return nil
}

// BeginRecoveryAuthorityTransition is explicit and returns a new complete code
// only after its original unsigned challenge and full envelope set are sealed.
func (w *Workflow) BeginRecoveryAuthorityTransition(ctx context.Context, id string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.authoritySessionLive(); err != nil {
		return "", err
	}
	r, a := w.state.Recovery, w.state.RecoveryAuthority
	if a.Pending != nil || !a.Vault.RotationRequired || !identifier.MatchString(id) || len(id) > 64 {
		return "", ErrRecoveryPending
	}
	if err := w.refreshAuthorityVault(ctx); err != nil {
		return "", err
	}
	authority, err := verifyRecoveryAuthorityChain(a.Vault)
	if err != nil {
		return "", err
	}
	var c recoveryAuthorityChallenge
	created := w.now().Unix()
	if err = w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovery-authority-challenges")), map[string]string{"operationId": id, "authorizationKind": "old-recovery", "chainMode": "continuous"}, &c); err != nil {
		return "", err
	}
	manifest := []cryptox.RecoveryEnvironmentVersion{}
	for _, e := range r.Vault.Environments {
		manifest = append(manifest, cryptox.RecoveryEnvironmentVersion{EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion})
	}
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].EnvironmentID < manifest[j].EnvironmentID })
	original, err := recoveryOriginalRecord(r.Vault)
	if err != nil {
		return "", err
	}
	if c.ExpiresAt <= created || c.ExpiresAt > created+125 || c.SessionHash != r.SessionHash || c.ExpectedSequence != strconv.FormatUint(a.Vault.Sequence, 10) || c.PreviousTransitionHash != authority.HeadHash() || c.OldRecoveryGeneration != r.RecoveryGeneration || c.OldRecoverySigningPublicKey != r.SigningPublicKey || c.OldRecoveryReceivingPublicKey != r.ReceivingPublicKey || c.AuthoritySet == nil || len(c.AuthoritySet) != 0 || c.IssuerEvidence != nil || c.LegacyState != nil || !sameJSONValue(c.EnvironmentManifest, manifest) || !sameJSONValue(c.OriginalInitialization, original) || !sameJSONValue(c.Transitions, a.Vault.Transitions) {
		return "", ErrRecoveryEvidence
	}
	old, err := strconv.ParseUint(r.RecoveryGeneration, 10, 64)
	if err != nil || old == ^uint64(0) {
		return "", ErrRecoveryEvidence
	}
	gen := strconv.FormatUint(old+1, 10)
	seed, err := cryptox.GenerateRecoverySeed()
	if err != nil {
		return "", err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, gen)
	if err != nil {
		return "", err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	root := r.Root
	root.RecoveryGeneration = gen
	root.RecoverySigningPublicKey = cryptox.EncodeBase64(keys.SigningPublic)
	root.RecoveryReceivingPublicKey = cryptox.EncodeBase64(keys.ReceivingPublic)
	root, err = cryptox.SignTrustRoot(r.AccountID, r.AccountGeneration, root, keys.SigningPrivate)
	if err != nil {
		return "", err
	}
	envs := []cryptox.RecoveryEnvelope{}
	for _, e := range manifest {
		key, e1 := cryptox.DecodeBase64(r.Keys[e.EnvironmentID], 32, 32)
		if e1 != nil {
			return "", e1
		}
		packet, e1 := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion, RecipientType: "recovery", RecipientID: r.AccountID, RecipientGeneration: gen, RecipientPublicKey: root.RecoveryReceivingPublicKey})
		clear(key)
		if e1 != nil {
			return "", e1
		}
		envs = append(envs, cryptox.RecoveryEnvelope{EnvironmentID: e.EnvironmentID, KeyVersion: e.KeyVersion, Envelope: cryptox.EncodeBase64(packet)})
	}
	mh, err := cryptox.RecoveryManifestHash(manifest)
	if err != nil {
		return "", err
	}
	eh, err := cryptox.RecoveryTransitionEnvelopesHash(envs)
	if err != nil {
		return "", err
	}
	rh, err := cryptox.RecoveryTrustRootReferenceHash(r.AccountID, r.AccountGeneration, root)
	if err != nil {
		return "", err
	}
	packet := cryptox.RecoveryTransitionSubmission{Transition: cryptox.RecoveryAuthorityTransition{AccountID: r.AccountID, AccountGeneration: r.AccountGeneration, OperationID: id, ChallengeID: c.ChallengeID, Nonce: c.Nonce, ExpiresAt: strconv.FormatInt(c.ExpiresAt, 10), SessionHash: r.SessionHash, ExpectedSequence: c.ExpectedSequence, PreviousTransitionHash: c.PreviousTransitionHash, OldRecoveryGeneration: r.RecoveryGeneration, OldRecoverySigningPublicKey: r.SigningPublicKey, OldRecoveryReceivingPublicKey: r.ReceivingPublicKey, NewRecoveryGeneration: gen, NewRecoverySigningPublicKey: root.RecoverySigningPublicKey, NewRecoveryReceivingPublicKey: root.RecoveryReceivingPublicKey, AuthorizationKind: "old-recovery", EnvironmentManifestHash: mh, EnvelopesHash: eh, NewTrustRootHash: rh, ChainMode: "continuous"}, EnvironmentManifest: manifest, AuthoritySet: []cryptox.RecoveryAdminAuthority{}, Envelopes: envs, NewTrustRoot: root}
	if _, err = packet.Transition.SigningBytes(); err != nil {
		return "", err
	}
	a.Pending = &recoveryAuthorityPending{CreatedAt: created, BaseSequence: a.Vault.Sequence, Packet: packet}
	if err = w.persist(); err != nil {
		a.Pending = nil
		return "", err
	}
	if err = w.bindRecoverySessionRotation(w.recoverySession); err != nil {
		return "", err
	}
	return cryptox.EncodeRecoveryCode(seed)
}

func (w *Workflow) queryAuthorityTransition(ctx context.Context) (bool, error) {
	a := w.state.RecoveryAuthority
	if a == nil || a.Pending == nil {
		return false, ErrRecoveryPending
	}
	p := a.Pending
	var s recoveryAuthorityStatus
	if err := w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovery-authority-transitions/"+p.Packet.Transition.OperationID)), nil, &s); err != nil {
		return false, err
	}
	if s.OperationID != p.Packet.Transition.OperationID {
		return false, ErrRecoveryEvidence
	}
	if !s.Accepted {
		if s.Sequence != 0 || s.ContentHash != "" || s.TransitionHash != "" || s.RecoveryEnrollmentHash != "" || p.AcceptedSequence != 0 {
			return false, ErrRecoveryEvidence
		}
		return false, nil
	}
	if p.ContentHash == "" {
		return false, ErrRecoveryEvidence
	}
	if err := verifyAuthorityReceipt(recoveryAuthorityReceipt{Sequence: s.Sequence, ContentHash: s.ContentHash, TransitionHash: s.TransitionHash, RecoveryEnrollmentHash: s.RecoveryEnrollmentHash}, s.OperationID, p.ContentHash, p.Packet.Transition.ExpectedSequence, false); err != nil {
		return false, err
	}
	p.AcceptedSequence = s.Sequence
	if err := w.persist(); err != nil {
		return true, errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	return true, nil
}

// CompleteRecoveryAuthorityTransition requires the entire freshly generated
// code. Once both signatures are sealed, the old process owner is erased and
// all uncertain retries use exactly this packet, nonce, ID and restricted token.
func (w *Workflow) CompleteRecoveryAuthorityTransition(ctx context.Context, completeNewCode string) (*RecoverySession, RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryLive(); err != nil {
		return nil, w.recoveryInfo(), err
	}
	a, r := w.state.RecoveryAuthority, w.state.Recovery
	if a == nil || a.Pending == nil {
		return nil, w.recoveryInfo(), ErrRecoveryPending
	}
	p := a.Pending
	t := p.Packet.Transition
	seed, err := cryptox.DecodeRecoveryCode(completeNewCode)
	if err != nil {
		return nil, w.recoveryInfo(), err
	}
	defer clear(seed)
	keys, err := cryptox.DeriveRecoveryKeys(seed, r.AccountID, r.AccountGeneration, t.NewRecoveryGeneration)
	if err != nil {
		return nil, w.recoveryInfo(), err
	}
	defer clear(keys.SigningPrivate)
	defer clear(keys.ReceivingPrivate)
	if cryptox.EncodeBase64(keys.SigningPublic) != t.NewRecoverySigningPublicKey || cryptox.EncodeBase64(keys.ReceivingPublic) != t.NewRecoveryReceivingPublicKey {
		return nil, w.recoveryInfo(), ErrRecoveryEvidence
	}
	if p.Applied {
		owner, err := w.newRecoverySession(keys.SigningPrivate)
		if err != nil {
			return nil, w.recoveryInfo(), err
		}
		if w.recoverySession != nil {
			w.recoverySession.Close()
		}
		w.recoverySession = owner
		return owner, w.recoveryInfo(), nil
	}
	accepted, err := w.queryAuthorityTransition(ctx)
	if err != nil {
		return nil, w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
	}
	if !accepted {
		expires, _ := strconv.ParseInt(t.ExpiresAt, 10, 64)
		if p.DeadlineClosed || w.now().Unix() >= expires || w.now().Unix() < p.CreatedAt-5 {
			p.DeadlineClosed = true
			if w.recoverySession != nil {
				w.recoverySession.Close()
				w.recoverySession = nil
			}
			save := w.persist()
			return nil, w.recoveryInfo(), errors.Join(ErrRecoveryExpired, save)
		}
		authority, err := verifyRecoveryAuthorityChain(a.Vault)
		if err != nil {
			return nil, w.recoveryInfo(), err
		}
		if p.Packet.AuthorizationSignature == "" {
			if err = w.authoritySessionLive(); err != nil {
				return nil, w.recoveryInfo(), err
			}
			sig, err := w.recoverySession.signAuthorityTransition(authority, p.Packet, w.now())
			if err != nil {
				return nil, w.recoveryInfo(), err
			}
			p.Packet.AuthorizationSignature = sig
			sig, err = cryptox.SignNewRecoveryTransition(authority, p.Packet, keys.SigningPrivate, w.now())
			if err != nil {
				p.Packet.AuthorizationSignature = ""
				return nil, w.recoveryInfo(), err
			}
			p.Packet.NewRecoverySignature = sig
			p.ContentHash, err = cryptox.RecoveryTransitionHash(p.Packet)
			if err != nil {
				return nil, w.recoveryInfo(), err
			}
		}
		// A failed save never posts. The original process key is retired only after
		// the complete signed packet is durably sealed by native storage.
		if err = w.persist(); err != nil {
			return nil, w.recoveryInfo(), err
		}
		if w.recoverySession != nil {
			w.recoverySession.Close()
			w.recoverySession = nil
		}
		var receipt recoveryAuthorityReceipt
		if err = w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityPath("recovery-authority-transitions")), p.Packet, &receipt); err != nil {
			return nil, w.recoveryInfo(), errors.Join(ErrRecoveryPending, err)
		}
		if err = verifyAuthorityReceipt(receipt, t.OperationID, p.ContentHash, t.ExpectedSequence, false); err != nil {
			return nil, w.recoveryInfo(), err
		}
		p.AcceptedSequence = receipt.Sequence
		if err = w.persist(); err != nil {
			return nil, w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
		}
	}
	var v recoveryAuthorityVault
	if err = w.recoveryRequest(ctx, w.accountPath(recoveryAuthorityVaultPath), nil, &v); err != nil {
		return nil, w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, recoveryVaultError(err))
	}
	if v.Sequence < p.AcceptedSequence || v.RotationRequired || v.TrustRoot == nil || *v.TrustRoot != p.Packet.NewTrustRoot || !sameRecoveryEnvelopeSet(v.Environments, p.Packet.Envelopes) || !sameJSONValue(v.OriginalInitialization, r.Vault.OriginalInitialization) {
		return nil, w.recoveryInfo(), syncclient.ErrAcceptedNotApplied
	}
	found := false
	for _, e := range v.Transitions {
		if e.Sequence == p.AcceptedSequence && sameJSONValue(e.Submission, p.Packet) {
			found = true
		}
	}
	if !found {
		return nil, w.recoveryInfo(), ErrRecoveryEvidence
	}
	envKeys, err := w.openAuthorityVault(v, keys, &r.Root)
	if err != nil {
		return nil, w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	if !sameJSONValue(envKeys, r.Keys) {
		return nil, w.recoveryInfo(), ErrRecoveryEvidence
	}
	beforeR, beforeA := clone(r), clone(a)
	r.RecoveryGeneration = v.RecoveryGeneration
	r.SigningPublicKey = v.RecoverySigningPublicKey
	r.ReceivingPublicKey = v.RecoveryReceivingPublicKey
	r.Root = *v.TrustRoot
	r.Keys = envKeys
	r.Vault = v.recoveryVaultWire
	a.Vault = v
	p.Applied = true
	if err = w.persist(); err != nil {
		w.state.Recovery = beforeR
		w.state.RecoveryAuthority = beforeA
		return nil, w.recoveryInfo(), errors.Join(syncclient.ErrAcceptedNotApplied, err)
	}
	owner, err := w.newRecoverySession(keys.SigningPrivate)
	if err != nil {
		return nil, w.recoveryInfo(), err
	}
	w.recoverySession = owner
	return owner, w.recoveryInfo(), nil
}

// QueryRecoveryAuthorityTransition returns only an exact checked receipt. It
// does not mark the vault applied or make the local device trusted.
func (w *Workflow) QueryRecoveryAuthorityTransition(ctx context.Context) (RecoveryInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.recoveryLive(); err != nil {
		return w.recoveryInfo(), err
	}
	_, err := w.queryAuthorityTransition(ctx)
	return w.recoveryInfo(), err
}

func authorityTransitionDigest(p cryptox.RecoveryTransitionSubmission) (string, error) {
	b, err := p.Transition.SigningBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
