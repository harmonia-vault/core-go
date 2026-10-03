package mobileworkflow

import (
	"bytes"
	"errors"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

// These are original accepted initialization grants, authenticated by both
// original purpose-bound signatures. No server-assigned sequence creates genesis.
func recoveryOriginalAuthorities(v recoveryVaultWire, root cryptox.TrustRoot) ([]cryptox.SignedGrantWire, error) {
	i := v.OriginalInitialization
	if i == nil || i.Sequence != 1 || i.Sequence > v.Sequence || i.Proof.AccountID != v.AccountID || i.Proof.AccountGeneration != v.AccountGeneration || i.Proposal.Device.ID != root.RootDeviceID || i.Proposal.Device.SigningPublicKey != root.RootSigningPublicKey || i.Proposal.Device.ReceivingPublicKey != root.RootReceivingPublicKey {
		return nil, ErrRecoveryEvidence
	}
	hash, err := i.Proposal.Hash(v.AccountID, v.AccountGeneration)
	if err != nil || hash != i.Proof.ProposalHash {
		return nil, ErrRecoveryEvidence
	}
	ed, err := cryptox.DecodeBase64(root.RootSigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyInitializationProof(i.Proof, i.DeviceSignature, ed) != nil {
		return nil, ErrRecoveryEvidence
	}
	oldRecovery, err := cryptox.DecodeBase64(i.Proposal.RecoverySigningPublicKey, 32, 32)
	if err != nil || cryptox.VerifyInitializationProof(i.Proof, i.RecoverySignature, oldRecovery) != nil {
		return nil, ErrRecoveryEvidence
	}
	out := make([]cryptox.SignedGrantWire, 0, len(i.Proposal.Environments))
	for _, e := range i.Proposal.Environments {
		out = append(out, e.Grant)
	}
	if len(out) == 0 {
		return nil, ErrRecoveryEvidence
	}
	return out, nil
}

// Current roles/expiry here are historical source data only. They never grant
// this recovering device any ordinary device session or management capability.
func (w *Workflow) verifyRecoveryOriginGrants(v recoveryVaultWire, root cryptox.TrustRoot) (map[string]bool, error) {
	if err := validateRecoveryEvidenceCandidate(v.IssuerEvidence); err != nil {
		return nil, err
	}
	if len(v.IssuerEvidence) == 0 || bytes.Equal(bytes.TrimSpace(v.IssuerEvidence), []byte("null")) {
		return nil, ErrRecoveryEvidence
	}
	var p cryptox.IssuerProofV2
	if err := decode(v.IssuerEvidence, &p); err != nil {
		return nil, errors.Join(ErrRecoveryEvidence, err)
	}
	if p.TrustRoot != root {
		return nil, ErrRecoveryEvidence
	}
	initial, err := recoveryOriginalAuthorities(v, root)
	if err != nil {
		return nil, err
	}
	pin := cryptox.PinnedIssuerRoot{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, DeviceID: root.RootDeviceID, SigningPublicKey: root.RootSigningPublicKey, ReceivingPublicKey: root.RootReceivingPublicKey}
	verified, err := cryptox.VerifyIssuerEvidenceV2(pin, p, initial...)
	if err != nil {
		return nil, errors.Join(ErrRecoveryEvidence, err)
	}
	envs := map[string]string{}
	for _, e := range v.Environments {
		if envs[e.EnvironmentID] != "" {
			return nil, ErrRecoveryEvidence
		}
		envs[e.EnvironmentID] = e.KeyVersion
	}
	targets := map[string]bool{}
	for _, target := range p.Targets {
		g, ok := verified.Authority(target.AuthorityHash)
		if !ok || targets[target.EnvironmentID] || envs[target.EnvironmentID] == "" || g.Grant.EnvironmentID != target.EnvironmentID || g.Grant.KeyVersion != envs[target.EnvironmentID] || g.Grant.Role == "none" {
			return nil, ErrRecoveryEvidence
		}
		if err := verified.VerifyHistoricalGrant(g); err != nil {
			return nil, errors.Join(ErrRecoveryEvidence, err)
		}
		targets[target.EnvironmentID] = true
	}
	if len(targets) != len(envs) {
		return nil, ErrRecoveryEvidence
	}
	accepted := map[string]bool{}
	accept := func(g syncclient.SignedGrant) error {
		signed := cryptox.SignedGrantWire{Grant: g.Grant, Signature: g.Signature}
		if err := verified.VerifyHistoricalGrant(signed); err != nil {
			return errors.Join(ErrRecoveryEvidence, err)
		}
		hash, err := cryptox.IssuerAuthorityHash(signed)
		if err != nil {
			return err
		}
		accepted[hash] = true
		return nil
	}
	// Old/deleted environment rows are not plaintext sources for this snapshot.
	// Their necessary parents are already fully checked in the signed graph.
	for _, g := range v.CurrentGrants {
		if g.Grant.AccountID != v.AccountID || g.Grant.AccountGeneration != v.AccountGeneration {
			return nil, ErrRecoveryEvidence
		}
		if envs[g.Grant.EnvironmentID] == g.Grant.KeyVersion && g.Grant.Role != "none" {
			if err := accept(g); err != nil {
				return nil, err
			}
		}
	}
	for _, event := range v.Events {
		if event.Authorization == nil {
			return nil, ErrRecoveryEvidence
		}
		if err := accept(*event.Authorization); err != nil {
			return nil, err
		}
	}
	return accepted, nil
}

// Classification is confined to the vault projection. Authentication failure
// and transport errors must not become evidence failures or accepted receipts.
func recoveryVaultError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syncclient.ErrTrustInvalidated) {
		return err
	}
	var rejected *syncclient.RequestError
	if errors.As(err, &rejected) {
		if rejected.Status == 401 || rejected.Status == 403 && rejected.Code == "recovery_session_stale" {
			return errors.Join(syncclient.ErrTrustInvalidated, err)
		}
		if rejected.Status == 403 {
			return errors.Join(ErrRecoveryEvidence, err)
		}
		return err
	}
	if errors.Is(err, errMobileResponseMalformed) {
		return errors.Join(ErrRecoveryEvidence, err)
	}
	return err
}
