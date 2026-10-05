package cryptox

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"time"
)

func (d *VerifiedRecoveryDAG) validateTransitionV2(s RecoveryTransitionSubmissionV2, now *time.Time) (*VerifiedIssuerProofV2, string, error) {
	v := d.current
	if v == nil {
		return nil, "", ErrInvalidWire
	}
	t := s.Transition
	if _, used := v.operations[t.OperationID]; used {
		return nil, "", ErrInvalidWire
	}
	if _, err := t.SigningBytes(); err != nil {
		return nil, "", err
	}
	if t.AccountID != v.pin.AccountID || t.AccountGeneration != v.pin.AccountGeneration || t.PreviousTransitionHash != v.head {
		return nil, "", ErrInvalidSignature
	}
	expected, _ := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	if expected < d.lastSequence {
		return nil, "", ErrInvalidWire
	}
	if now != nil {
		if err := ValidateRecoveryChallenge(t.ExpiresAt, *now); err != nil {
			return nil, "", err
		}
	}
	// 当前差异材料中的旧公钥也必须先退役，不能等接受后才记录。
	// 仅构造候选集合，验证失败不改变先前受信链。
	seenKeys := make(map[string]bool, len(v.usedRecoveryKeys)+2)
	for pub, used := range v.usedRecoveryKeys {
		seenKeys[pub] = used
	}
	seenKeys[v.pin.SigningPublicKey] = true
	seenKeys[v.pin.ReceivingPublicKey] = true
	if t.OldRecoveryGeneration != v.recoveryGeneration || t.OldRecoverySigningPublicKey != v.signingPublic || t.OldRecoveryReceivingPublicKey != v.receivingPublic {
		return nil, "", ErrInvalidSignature
	}
	r := s.NewTrustRoot
	if !recoveryRootMatches(v.pin, r) || r.RecoveryGeneration != t.NewRecoveryGeneration || r.RecoverySigningPublicKey != t.NewRecoverySigningPublicKey || r.RecoveryReceivingPublicKey != t.NewRecoveryReceivingPublicKey {
		return nil, "", ErrInvalidSignature
	}
	for _, pub := range []string{t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey} {
		if seenKeys[pub] || d.publicOwners[pub] != "" {
			return nil, "", ErrInvalidSignature
		}
	}
	h, err := RecoveryTrustRootReferenceHash(t.AccountID, t.AccountGeneration, r)
	if err != nil || h != t.NewTrustRootHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = RecoveryManifestHash(s.EnvironmentManifest)
	if err != nil || h != t.EnvironmentManifestHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = RecoveryTransitionEnvelopesHash(s.Envelopes)
	if err != nil || h != t.EnvelopesHash || len(s.Envelopes) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidSignature
	}
	for i, e := range s.Envelopes {
		if e.EnvironmentID != s.EnvironmentManifest[i].EnvironmentID || e.KeyVersion != s.EnvironmentManifest[i].KeyVersion {
			return nil, "", ErrInvalidSignature
		}
	}
	encoded, err := json.Marshal(s)
	if err != nil || len(encoded) > MaxRecoveryAuthorityBytes {
		return nil, "", ErrInvalidWire
	}
	if t.AuthorizationKind == "old-recovery" {
		if s.AuthoritySet == nil || len(s.AuthoritySet) != 0 || s.IssuerEvidence != nil {
			return nil, "", ErrInvalidWire
		}
		return nil, v.signingPublic, nil
	}
	if s.IssuerEvidence == nil || len(s.AuthoritySet) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidWire
	}
	h, err = RecoveryAdminAuthoritiesHash(s.AuthoritySet)
	if err != nil || h != t.AuthoritySetHash {
		return nil, "", ErrInvalidSignature
	}
	h, err = s.IssuerEvidence.Hash()
	if err != nil || h != t.IssuerEvidenceHash {
		return nil, "", ErrInvalidSignature
	}
	p, err := d.sourceGraph(*s.IssuerEvidence, expected)
	if err != nil {
		return nil, "", err
	}
	if len(p.targets) != len(s.EnvironmentManifest) {
		return nil, "", ErrInvalidSignature
	}
	actor, ok := p.identities[t.AuthorizerDeviceID]
	if !ok {
		return nil, "", ErrInvalidSignature
	}
	for i, row := range s.AuthoritySet {
		manifest := s.EnvironmentManifest[i]
		g, ok := p.Authority(row.AuthorityHash)
		a := g.Grant
		if !ok || row.EnvironmentID != manifest.EnvironmentID || row.KeyVersion != manifest.KeyVersion || a.AccountID != t.AccountID || a.AccountGeneration != t.AccountGeneration || a.EnvironmentID != row.EnvironmentID || a.KeyVersion != row.KeyVersion || a.GrantGeneration != row.GrantGeneration || a.ExpiresAt != row.ExpiresAt || a.Role != "admin" || p.VerifyTarget(g, t.AuthorizerDeviceID, actor.signing, actor.receiving) != nil {
			return nil, "", ErrInvalidSignature
		}
		expiry, err := strconv.ParseInt(a.ExpiresAt, 10, 64)
		if err != nil || expiry < 0 || now != nil && expiry != 0 && expiry <= now.Unix() {
			return nil, "", ErrInvalidSignature
		}
	}
	for _, identity := range p.identities {
		for _, pub := range []string{t.NewRecoverySigningPublicKey, t.NewRecoveryReceivingPublicKey} {
			if pub == identity.signing || pub == identity.receiving {
				return nil, "", ErrInvalidSignature
			}
		}
	}
	return p, actor.signing, nil
}
func (d *VerifiedRecoveryDAG) validateRecoveredV2(s RecoveredDeviceSubmissionV2, now *time.Time) (*VerifiedIssuerProofV2, error) {
	v := d.current
	if v == nil || len(v.operations) == 0 || s.CertificateVersion != "5" || len(s.Capabilities) != 1 || s.Capabilities[0] != RecoveryDAGCapability {
		return nil, ErrInvalidWire
	}
	c := s.Enrollment
	if _, e := c.SigningBytes(); e != nil {
		return nil, e
	}
	if c.AccountID != v.pin.AccountID || c.AccountGeneration != v.pin.AccountGeneration || c.RecoveryGeneration != v.recoveryGeneration || c.RecoveryTransitionHash != v.head {
		return nil, ErrInvalidSignature
	}
	expected, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if expected < d.lastSequence {
		return nil, ErrInvalidWire
	}
	if now != nil {
		if e := ValidateRecoveryChallenge(c.ExpiresAt, *now); e != nil {
			return nil, e
		}
	}
	h, e := RecoveredDeviceRightsHash(s.SelectedRights)
	if e != nil || h != c.SelectedRightsHash {
		return nil, ErrInvalidSignature
	}
	h, e = RecoveredDeviceGrantsHash(s.Grants)
	if e != nil || h != c.GrantsHash {
		return nil, ErrInvalidSignature
	}
	h, e = RecoveredDeviceEnvelopesHash(s.Envelopes)
	if e != nil || h != c.EnvelopesHash || len(s.SelectedRights) != len(s.Grants) || len(s.Envelopes) != len(s.Grants) {
		return nil, ErrInvalidSignature
	}
	h, e = s.IssuerEvidence.Hash()
	if e != nil || h != c.IssuerEvidenceHash {
		return nil, ErrInvalidSignature
	}
	r, e := sourceRoot(s.IssuerEvidence)
	if e != nil {
		return nil, e
	}
	if r.RecoveryGeneration != v.recoveryGeneration || r.RecoverySigningPublicKey != v.signingPublic || r.RecoveryReceivingPublicKey != v.receivingPublic {
		return nil, ErrInvalidSignature
	}
	p, e := d.sourceGraph(s.IssuerEvidence, expected)
	if e != nil {
		return nil, e
	}
	if _, known := d.identities[c.DeviceID]; known {
		return nil, ErrInvalidSignature
	}
	if _, known := p.identities[c.DeviceID]; known {
		return nil, ErrInvalidSignature
	}
	for _, identity := range p.identities {
		for _, pub := range []string{c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey} {
			if pub == identity.signing || pub == identity.receiving {
				return nil, ErrInvalidSignature
			}
		}
	}
	for _, pub := range []string{c.DeviceSigningPublicKey, c.DeviceReceivingPublicKey} {
		if d.publicOwners[pub] != "" || v.usedRecoveryKeys[pub] {
			return nil, ErrInvalidSignature
		}
	}
	key, e := DecodeBase64(c.DeviceSigningPublicKey, 32, 32)
	if e != nil {
		return nil, e
	}
	for i, row := range s.SelectedRights {
		g := s.Grants[i].Grant
		envelope := s.Envelopes[i]
		if g.AccountID != c.AccountID || g.AccountGeneration != c.AccountGeneration || g.IssuerDeviceID != c.DeviceID || g.SubjectDeviceID != c.DeviceID || g.SubjectSigningPublicKey != c.DeviceSigningPublicKey || g.SubjectReceivingPublicKey != c.DeviceReceivingPublicKey || g.EnvironmentID != row.EnvironmentID || g.KeyVersion != row.KeyVersion || g.Role != row.Role || g.ExpiresAt != row.ExpiresAt || g.GrantGeneration != "1" || envelope.EnvironmentID != row.EnvironmentID || envelope.KeyVersion != row.KeyVersion || envelope.Envelope != g.Envelope {
			return nil, ErrInvalidSignature
		}
		if e = VerifyGrant(s.Grants[i].SignedGrant(), key); e != nil {
			return nil, e
		}
		target, exists := p.targets[row.EnvironmentID]
		source, known := p.Authority(target)
		if !exists || !known || source.Grant.EnvironmentID != row.EnvironmentID || source.Grant.KeyVersion != row.KeyVersion {
			return nil, ErrInvalidSignature
		}
		expiry, _ := strconv.ParseInt(row.ExpiresAt, 10, 64)
		if now != nil && expiry != 0 && expiry <= now.Unix() {
			return nil, ErrInvalidSignature
		}
	}
	encoded, e := json.Marshal(s)
	if e != nil || len(encoded) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	return p, nil
}

// 各入口只签已验证的用途包，不提供任意字节签名接口。
func SignOldRecoveryTransitionV2(d *VerifiedRecoveryDAG, s RecoveryTransitionSubmissionV2, key ed25519.PrivateKey, now time.Time) (string, error) {
	if d == nil || s.Transition.AuthorizationKind != "old-recovery" {
		return "", ErrInvalidWire
	}
	_, pub, e := d.validateTransitionV2(s, &now)
	if e != nil {
		return "", e
	}
	b, e := s.Transition.SigningBytes()
	if e != nil {
		return "", e
	}
	return signRecoveryPurpose(key, pub, b)
}
func SignAllAdminRecoveryTransitionV2(d *VerifiedRecoveryDAG, s RecoveryTransitionSubmissionV2, key ed25519.PrivateKey, now time.Time) (string, error) {
	if d == nil || s.Transition.AuthorizationKind != "all-environments-admin" {
		return "", ErrInvalidWire
	}
	_, pub, e := d.validateTransitionV2(s, &now)
	if e != nil {
		return "", e
	}
	b, e := s.Transition.SigningBytes()
	if e != nil {
		return "", e
	}
	return signRecoveryPurpose(key, pub, b)
}
func SignNewRecoveryTransitionV2(d *VerifiedRecoveryDAG, s RecoveryTransitionSubmissionV2, key ed25519.PrivateKey, now time.Time) (string, error) {
	if d == nil {
		return "", ErrInvalidWire
	}
	_, authorizer, e := d.validateTransitionV2(s, &now)
	if e != nil {
		return "", e
	}
	b, e := s.Transition.SigningBytes()
	if e != nil {
		return "", e
	}
	pub, e := DecodeBase64(authorizer, 32, 32)
	if e != nil {
		return "", e
	}
	if e = verify(pub, b, s.AuthorizationSignature); e != nil {
		return "", e
	}
	return signRecoveryPurpose(key, s.Transition.NewRecoverySigningPublicKey, b)
}
func SignRecoveredDeviceByRecoveryV2(d *VerifiedRecoveryDAG, s RecoveredDeviceSubmissionV2, key ed25519.PrivateKey, now time.Time) (string, error) {
	if d == nil {
		return "", ErrInvalidWire
	}
	if _, e := d.validateRecoveredV2(s, &now); e != nil {
		return "", e
	}
	b, e := s.Enrollment.SigningBytes()
	if e != nil {
		return "", e
	}
	return signRecoveryPurpose(key, d.current.signingPublic, b)
}
func SignRecoveredDeviceAfterHPKEV2(d *VerifiedRecoveryDAG, s RecoveredDeviceSubmissionV2, key ed25519.PrivateKey, receivingPrivate []byte, now time.Time) (string, error) {
	if d == nil {
		return "", ErrInvalidWire
	}
	if _, e := d.validateRecoveredV2(s, &now); e != nil {
		return "", e
	}
	c := s.Enrollment
	x, e := ecdh.X25519().NewPrivateKey(receivingPrivate)
	if e != nil || EncodeBase64(x.PublicKey().Bytes()) != c.DeviceReceivingPublicKey {
		return "", ErrInvalidSignature
	}
	b, e := c.SigningBytes()
	if e != nil {
		return "", e
	}
	pub, e := DecodeBase64(d.current.signingPublic, 32, 32)
	if e != nil {
		return "", e
	}
	if e = verify(pub, b, s.RecoverySignature); e != nil {
		return "", e
	}
	for _, g := range s.Grants {
		packet, e := DecodeBase64(g.Grant.Envelope, 80, 80)
		if e != nil {
			return "", e
		}
		env := g.Grant
		k, e := UnwrapEnvironmentKey(receivingPrivate, EnvelopeContext{AccountID: env.AccountID, AccountGeneration: env.AccountGeneration, EnvironmentID: env.EnvironmentID, KeyVersion: env.KeyVersion, RecipientType: "device", RecipientID: env.SubjectDeviceID, RecipientGeneration: env.GrantGeneration, RecipientPublicKey: env.SubjectReceivingPublicKey}, packet)
		if e != nil {
			return "", e
		}
		clear(k)
	}
	return signRecoveryPurpose(key, c.DeviceSigningPublicKey, b)
}

func verifyAcceptedTransitionV2(d *VerifiedRecoveryDAG, r AcceptedRecoveryTransitionV2) (*VerifiedRecoveryAuthority, error) {
	_, actor, e := d.validateTransitionV2(r.Submission, nil)
	if e != nil {
		return nil, e
	}
	s := r.Submission
	t := s.Transition
	n, _ := strconv.ParseUint(t.ExpectedSequence, 10, 64)
	if r.Sequence != n+1 || len(d.current.operations) >= MaxRecoveryTransitions {
		return nil, ErrInvalidWire
	}
	b, e := t.SigningBytes()
	if e != nil {
		return nil, e
	}
	for _, pair := range [][2]string{{actor, s.AuthorizationSignature}, {t.NewRecoverySigningPublicKey, s.NewRecoverySignature}} {
		pub, e := DecodeBase64(pair[0], 32, 32)
		if e != nil {
			return nil, e
		}
		if e = verify(pub, b, pair[1]); e != nil {
			return nil, e
		}
	}
	h, e := RecoveryTransitionHashV2(s)
	if e != nil {
		return nil, e
	}
	v := d.current
	ops := map[string]string{}
	for k, x := range v.operations {
		ops[k] = x
	}
	ops[t.OperationID] = h
	keys := map[string]bool{}
	for k, x := range v.usedRecoveryKeys {
		keys[k] = x
	}
	keys[t.OldRecoverySigningPublicKey] = true
	keys[t.OldRecoveryReceivingPublicKey] = true

	keys[t.NewRecoverySigningPublicKey] = true
	keys[t.NewRecoveryReceivingPublicKey] = true
	return &VerifiedRecoveryAuthority{pin: v.pin, initial: v.InitialAuthorities(), recoveryGeneration: t.NewRecoveryGeneration, signingPublic: t.NewRecoverySigningPublicKey, receivingPublic: t.NewRecoveryReceivingPublicKey, head: h, sequence: r.Sequence, operations: ops, usedRecoveryKeys: keys}, nil
}
func verifyAcceptedRecoveredV2(d *VerifiedRecoveryDAG, r AcceptedRecoveredDeviceV2) (*VerifiedRecoveredDevice, error) {
	if _, e := d.validateRecoveredV2(r.Submission, nil); e != nil {
		return nil, e
	}
	s := r.Submission
	c := s.Enrollment
	n, _ := strconv.ParseUint(c.ExpectedSequence, 10, 64)
	if r.Sequence != n+1 {
		return nil, ErrInvalidWire
	}
	b, e := c.SigningBytes()
	if e != nil {
		return nil, e
	}
	for _, pair := range [][2]string{{d.current.signingPublic, s.RecoverySignature}, {c.DeviceSigningPublicKey, s.DeviceSignature}} {
		pub, e := DecodeBase64(pair[0], 32, 32)
		if e != nil {
			return nil, e
		}
		if e = verify(pub, b, pair[1]); e != nil {
			return nil, e
		}
	}
	h, e := RecoveredDeviceReferenceHashV2(s)
	if e != nil {
		return nil, e
	}
	grants := map[string]SignedGrantWire{}
	for _, g := range s.Grants {
		hash, e := IssuerAuthorityHash(g)
		if e != nil {
			return nil, e
		}
		grants[hash] = g
	}
	return &VerifiedRecoveredDevice{deviceID: c.DeviceID, signingPublic: c.DeviceSigningPublicKey, receivingPublic: c.DeviceReceivingPublicKey, referenceHash: h, grants: grants}, nil
}
