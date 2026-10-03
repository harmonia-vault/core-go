package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"sort"
	"strconv"
)

// 该接口必须由本机原生加密Store提供；public原包无seed、私钥、token或明文值。
type DAGRecoveryJournal interface {
	Save(ProtectedDAGOperation) error
	Load() (ProtectedDAGOperation, error)
}
type ProtectedDAGOperation struct {
	Version           int                                  `json:"version"`
	Endpoint          string                               `json:"endpoint"`
	AccountID         string                               `json:"accountId"`
	AccountGeneration uint64                               `json:"accountGeneration"`
	Pin               cryptox.PinnedIssuerRoot             `json:"pin"`
	Kind              string                               `json:"kind"`
	OperationID       string                               `json:"operationId"`
	ContentHash       string                               `json:"contentHash"`
	Transition        *cryptox.RecoveryTransitionCommandV2 `json:"transition,omitempty"`
	Recovered         *cryptox.RecoveredDeviceCommandV2    `json:"recovered,omitempty"`
	Attempted         bool                                 `json:"attempted"`
	AcceptedSequence  uint64                               `json:"acceptedSequence"`
	Applied           bool                                 `json:"applied"`
}

func cloneDAGOperation(p ProtectedDAGOperation) ProtectedDAGOperation {
	b, _ := json.Marshal(p)
	var out ProtectedDAGOperation
	_ = json.Unmarshal(b, &out)
	return out
}
func (s *DAGRecoverySession) savePending(p ProtectedDAGOperation) error {
	if e := s.config.Journal.Save(cloneDAGOperation(p)); e != nil {
		return e
	}
	s.pending = &p
	return nil
}
func (s *DAGRecoverySession) baseOperation(kind, id, hash string) ProtectedDAGOperation {
	return ProtectedDAGOperation{Version: 1, Endpoint: s.config.Endpoint, AccountID: s.config.AccountID, AccountGeneration: s.config.AccountGeneration, Pin: s.pin, Kind: kind, OperationID: id, ContentHash: hash}
}
func (s *DAGRecoverySession) checkPending() error {
	if s.pending == nil {
		return ErrDAGRecoveryState
	}
	stored, e := s.config.Journal.Load()
	if e != nil {
		return e
	}
	if !sameJSON(stored, *s.pending) {
		return errors.New("protected original DAG packet changed")
	}
	return nil
}

// 新码仅显示一次；保存的是公钥。只有完整重输并持新seed签一次nonce才产生待提交原包。
func (s *DAGRecoverySession) BeginTransition(ctx context.Context, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return "", e
	}
	if !enrollmentID.MatchString(id) || s.transitionChallenge != nil || s.pending != nil && !s.pending.Applied {
		return "", ErrDAGRecoveryState
	}
	if e := s.refresh(ctx); e != nil {
		return "", e
	}
	var preparation DAGTransitionPreparation
	if s.config.Preparation != nil {
		var err error
		preparation, err = s.saveOriginalIntent(id)
		if err != nil {
			return "", err
		}
	}
	var c DAGTransitionChallenge
	if e := s.request(ctx, "POST", dagPath("recovery-authority-challenges-v2"), s.token, map[string]string{"operationId": id, "authorizationKind": "old-recovery", "chainMode": "continuous"}, &c); e != nil {
		if s.config.Preparation != nil {
			return "", errors.Join(ErrDAGPreparationPending, e)
		}
		return "", e
	}
	head, e := s.proof.RecoveryCheckpoint()
	if e != nil {
		return "", e
	}
	if c.OperationID != id || c.AccountGeneration != strconv.FormatUint(s.config.AccountGeneration, 10) || c.AuthorizationKind != "old-recovery" || c.ChainMode != "continuous" || c.AuthorizerDeviceID != "" || c.SessionHash != digest([]byte(s.token)) || c.ExpectedSequence != strconv.FormatUint(s.vault.Sequence, 10) || c.OldRecoveryGeneration != head.RecoveryGeneration || c.OldRecoverySigningPublicKey != head.SigningPublicKey || c.OldRecoveryReceivingPublicKey != head.ReceivingPublicKey || c.PreviousTransitionHash != head.TransitionHead || !sameJSON(c.DependencyBundle, s.vault.DependencyBundle) || c.IssuerEvidence != nil || len(c.AuthoritySet) != 0 || c.ExpiresAt <= s.config.Now().Unix() || c.ExpiresAt > s.config.Now().Unix()+125 {
		return "", cryptox.ErrInvalidWire
	}
	versions := []cryptox.RecoveryEnvironmentVersion{}
	for _, row := range s.vault.Environments {
		versions = append(versions, cryptox.RecoveryEnvironmentVersion{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion})
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].EnvironmentID < versions[j].EnvironmentID })
	if !sameJSON(c.EnvironmentManifest, versions) {
		return "", cryptox.ErrInvalidWire
	}
	seed, e := cryptox.GenerateRecoverySeed()
	if e != nil {
		return "", e
	}
	defer clear(seed)
	g, e := parsePositive(head.RecoveryGeneration)
	if e != nil || g == ^uint64(0) {
		return "", cryptox.ErrInvalidWire
	}
	next := strconv.FormatUint(g+1, 10)
	keys, e := cryptox.DeriveRecoveryKeys(seed, s.config.AccountID, c.AccountGeneration, next)
	if e != nil {
		return "", e
	}
	defer clearRecoveryKeys(&keys)
	if s.config.Preparation != nil {
		preparation.Phase = "prepared"
		preparation.Challenge = &c
		preparation.NewRecoveryGeneration = next
		preparation.NewSigningPublicKey = cryptox.EncodeBase64(keys.SigningPublic)
		preparation.NewReceivingPublicKey = cryptox.EncodeBase64(keys.ReceivingPublic)
		if e = s.config.Preparation.SaveTransitionPreparation(preparation); e != nil {
			return "", e
		}
	}
	s.transitionChallenge = &c
	s.newGeneration = next
	s.newSigning = cryptox.EncodeBase64(keys.SigningPublic)
	s.newReceiving = cryptox.EncodeBase64(keys.ReceivingPublic)
	return cryptox.EncodeRecoveryCode(seed)
}
func (s *DAGRecoverySession) SealTransition(ctx context.Context, completeNewCode string) (ProtectedDAGOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return ProtectedDAGOperation{}, e
	}
	if s.transitionChallenge == nil || s.pending != nil && !s.pending.Applied {
		return ProtectedDAGOperation{}, ErrDAGRecoveryState
	}
	c := *s.transitionChallenge
	if s.config.Preparation != nil {
		p, err := s.config.Preparation.LoadTransitionPreparation()
		if err != nil {
			return ProtectedDAGOperation{}, err
		}
		if ValidateDAGTransitionPreparation(p) != nil || p.Phase != "prepared" || !sameJSON(p.Challenge, &c) || p.NewRecoveryGeneration != s.newGeneration || p.NewSigningPublicKey != s.newSigning || p.NewReceivingPublicKey != s.newReceiving {
			return ProtectedDAGOperation{}, ErrDAGPreparationConflict
		}
	}
	seed, e := cryptox.DecodeRecoveryCode(completeNewCode)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	defer clear(seed)
	keys, e := cryptox.DeriveRecoveryKeys(seed, s.config.AccountID, c.AccountGeneration, s.newGeneration)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	keep := false
	defer func() {
		if !keep {
			clearRecoveryKeys(&keys)
		}
	}()
	if cryptox.EncodeBase64(keys.SigningPublic) != s.newSigning || cryptox.EncodeBase64(keys.ReceivingPublic) != s.newReceiving {
		return ProtectedDAGOperation{}, ErrDAGNewCodeMismatch
	}
	sub := cryptox.RecoveryTransitionSubmissionV2{EnvironmentManifest: c.EnvironmentManifest, AuthoritySet: []cryptox.RecoveryAdminAuthority{}, IssuerEvidence: nil, Envelopes: []cryptox.RecoveryEnvelope{}, LegacyState: nil}
	root := s.vault.TrustRoot
	root.RecoveryGeneration = s.newGeneration
	root.RecoverySigningPublicKey = s.newSigning
	root.RecoveryReceivingPublicKey = s.newReceiving
	root, e = cryptox.SignTrustRoot(s.config.AccountID, c.AccountGeneration, root, keys.SigningPrivate)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	sub.NewTrustRoot = root
	for _, row := range c.EnvironmentManifest {
		key := s.environmentKeys[row.EnvironmentID]
		if len(key) != 32 {
			return ProtectedDAGOperation{}, cryptox.ErrInvalidWire
		}
		packet, e := cryptox.WrapEnvironmentKey(key, cryptox.EnvelopeContext{AccountID: s.config.AccountID, AccountGeneration: c.AccountGeneration, EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, RecipientType: "recovery", RecipientID: s.config.AccountID, RecipientGeneration: s.newGeneration, RecipientPublicKey: s.newReceiving})
		if e != nil {
			return ProtectedDAGOperation{}, e
		}
		sub.Envelopes = append(sub.Envelopes, cryptox.RecoveryEnvelope{EnvironmentID: row.EnvironmentID, KeyVersion: row.KeyVersion, Envelope: cryptox.EncodeBase64(packet)})
	}
	mh, e := cryptox.RecoveryManifestHash(sub.EnvironmentManifest)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	eh, e := cryptox.RecoveryTransitionEnvelopesHash(sub.Envelopes)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	rh, e := cryptox.RecoveryTrustRootReferenceHash(s.config.AccountID, c.AccountGeneration, root)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	sub.Transition = cryptox.RecoveryAuthorityTransitionV2{AccountID: s.config.AccountID, AccountGeneration: c.AccountGeneration, OperationID: c.OperationID, ChallengeID: c.ChallengeID, Nonce: c.Nonce, ExpiresAt: strconv.FormatInt(c.ExpiresAt, 10), SessionHash: c.SessionHash, ExpectedSequence: c.ExpectedSequence, PreviousTransitionHash: c.PreviousTransitionHash, OldRecoveryGeneration: c.OldRecoveryGeneration, OldRecoverySigningPublicKey: c.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: c.OldRecoveryReceivingPublicKey, NewRecoveryGeneration: s.newGeneration, NewRecoverySigningPublicKey: s.newSigning, NewRecoveryReceivingPublicKey: s.newReceiving, AuthorizationKind: "old-recovery", AuthorizerDeviceID: "", EnvironmentManifestHash: mh, AuthoritySetHash: "", IssuerEvidenceHash: "", EnvelopesHash: eh, NewTrustRootHash: rh, ChainMode: "continuous", LegacyStateHash: ""}
	sub.AuthorizationSignature, e = cryptox.SignOldRecoveryTransitionV2(s.proof, sub, s.keys.SigningPrivate, s.config.Now())
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	sub.NewRecoverySignature, e = cryptox.SignNewRecoveryTransitionV2(s.proof, sub, keys.SigningPrivate, s.config.Now())
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	command := cryptox.RecoveryTransitionCommandV2{Submission: sub, DependencyBundle: c.DependencyBundle}
	raw, e := json.Marshal(command)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	if _, e = cryptox.DecodeRecoveryTransitionCommandV2(raw); e != nil {
		return ProtectedDAGOperation{}, e
	}
	hash, e := cryptox.RecoveryTransitionHashV2(sub)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	p := s.baseOperation("transition-v2", c.OperationID, hash)
	p.Transition = &command
	if e = s.savePending(p); e != nil {
		return ProtectedDAGOperation{}, e
	}
	clearRecoveryKeys(&s.nextKeys)
	s.nextKeys = keys
	keep = true
	return cloneDAGOperation(p), nil
}
func expectedDAGReceipt(out DAGReceipt, id, hash, expected string, recovered, status bool) error {
	n, e := strconv.ParseUint(expected, 10, 64)
	if e != nil || n >= 9007199254740991 || out.Sequence != n+1 || out.ContentHash != hash || status && (!out.Accepted || out.OperationID != id) {
		return cryptox.ErrInvalidWire
	}
	if recovered {
		if out.RecoveryEnrollmentHash != hash || out.TransitionHash != "" {
			return cryptox.ErrInvalidWire
		}
	} else if out.TransitionHash != hash || out.RecoveryEnrollmentHash != "" {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func (s *DAGRecoverySession) query(ctx context.Context, p ProtectedDAGOperation) (DAGReceipt, error) {
	if e := validateProtectedDAGOperation(p); e != nil {
		return DAGReceipt{}, e
	}
	op, expected := "recovery-authority-transitions-v2", p.Transition
	if p.Kind == "recovered-v2" {
		op = "recovered-devices-v2"
	}
	wire := dagStatusReceipt{recovered: p.Kind == "recovered-v2"}
	if e := s.request(ctx, "GET", dagPath(op+"/"+p.OperationID), s.token, nil, &wire); e != nil {
		return DAGReceipt{}, e
	}
	out := wire.value
	if out.OperationID != p.OperationID {
		return out, cryptox.ErrInvalidWire
	}
	if !out.Accepted {
		if out.Sequence != 0 || out.ContentHash != "" || out.TransitionHash != "" || out.RecoveryEnrollmentHash != "" || p.AcceptedSequence != 0 {
			return out, cryptox.ErrInvalidWire
		}
		return out, nil
	}
	base := ""
	if expected != nil {
		base = expected.Submission.Transition.ExpectedSequence
	} else {
		base = p.Recovered.Submission.Enrollment.ExpectedSequence
	}
	return out, expectedDAGReceipt(out, p.OperationID, p.ContentHash, base, p.Kind == "recovered-v2", true)
}
func (s *DAGRecoverySession) RetryTransition(ctx context.Context) (DAGRecoveryInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return DAGRecoveryInfo{}, e
	}
	if s.pending == nil || s.pending.Kind != "transition-v2" || s.pending.Transition == nil {
		return DAGRecoveryInfo{}, ErrDAGRecoveryState
	}
	if e := s.checkPending(); e != nil {
		return DAGRecoveryInfo{}, e
	}
	p := cloneDAGOperation(*s.pending)
	if p.Applied {
		if e := s.refresh(ctx); e != nil {
			return DAGRecoveryInfo{}, e
		}
		if s.vault.RotationRequired || s.vault.RecoveryHeadHash != p.ContentHash {
			return DAGRecoveryInfo{}, ErrDAGRecoveryState
		}
		return DAGRecoveryInfo{RecoveryGeneration: s.vault.RecoveryGeneration, Sequence: s.vault.Sequence, Environments: len(s.vault.Environments), RotationRequired: false, TrustedDevice: false, ExpiresAt: s.expires}, nil
	}
	out, e := s.query(ctx, p)
	if e != nil {
		return DAGRecoveryInfo{}, errors.Join(ErrEnrollmentPending, e)
	}
	if !out.Accepted {
		t := p.Transition.Submission.Transition
		expires, _ := strconv.ParseInt(t.ExpiresAt, 10, 64)
		if t.SessionHash != digest([]byte(s.token)) || s.config.Now().Unix() >= expires {
			return DAGRecoveryInfo{}, ErrDAGRecoveryState
		}
		p.Attempted = true
		if e = s.savePending(p); e != nil {
			return DAGRecoveryInfo{}, e
		}
		if e = s.request(ctx, "POST", dagPath("recovery-authority-transitions-v2"), s.token, p.Transition, &out); e != nil {
			return DAGRecoveryInfo{}, errors.Join(ErrEnrollmentPending, e)
		}
		if e = expectedDAGReceipt(out, p.OperationID, p.ContentHash, t.ExpectedSequence, false, false); e != nil {
			return DAGRecoveryInfo{}, errors.Join(ErrEnrollmentPending, e)
		}
	}
	p.AcceptedSequence = out.Sequence
	if e = s.savePending(p); e != nil {
		return DAGRecoveryInfo{}, errors.Join(ErrAcceptedNotApplied, e)
	}
	if len(s.nextKeys.SigningPrivate) != ed25519.PrivateKeySize {
		return DAGRecoveryInfo{}, errors.Join(ErrAcceptedNotApplied, ErrDAGRecoveryState)
	}
	clearRecoveryKeys(&s.keys)
	s.keys = cryptox.RecoveryKeys{SigningPrivate: bytes.Clone(s.nextKeys.SigningPrivate), SigningPublic: bytes.Clone(s.nextKeys.SigningPublic), ReceivingPrivate: bytes.Clone(s.nextKeys.ReceivingPrivate), ReceivingPublic: bytes.Clone(s.nextKeys.ReceivingPublic)}
	if e = s.refresh(ctx); e != nil {
		return DAGRecoveryInfo{}, errors.Join(ErrAcceptedNotApplied, e)
	}
	if s.vault.RotationRequired || s.vault.RecoveryHeadHash != p.ContentHash || s.vault.Sequence < p.AcceptedSequence {
		return DAGRecoveryInfo{}, errors.Join(ErrAcceptedNotApplied, cryptox.ErrInvalidWire)
	}
	p.Applied = true
	if e = s.savePending(p); e != nil {
		return DAGRecoveryInfo{}, errors.Join(ErrAcceptedNotApplied, e)
	}
	s.transitionChallenge = nil
	clearRecoveryKeys(&s.nextKeys)
	return DAGRecoveryInfo{RecoveryGeneration: s.vault.RecoveryGeneration, Sequence: s.vault.Sequence, Environments: len(s.vault.Environments), RotationRequired: false, TrustedDevice: false, ExpiresAt: s.expires}, nil
}

// 单独状态查询不会重签、申请nonce、切换私钥或授予设备管理权限。
func (s *DAGRecoverySession) QueryOriginalOperation(ctx context.Context, p ProtectedDAGOperation) (DAGReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return DAGReceipt{}, e
	}
	if p.Version != 1 || p.Endpoint != s.config.Endpoint || p.AccountID != s.config.AccountID || p.AccountGeneration != s.config.AccountGeneration || p.Pin != s.pin || !enrollmentID.MatchString(p.OperationID) {
		return DAGReceipt{}, cryptox.ErrInvalidWire
	}
	return s.query(ctx, p)
}

type DAGRecoveredResult struct {
	Accepted cryptox.AcceptedRecoveredDeviceV2
	Evidence cryptox.IssuerRecoveryDAG
	Pin      cryptox.PinnedIssuerRoot
}

func (s *DAGRecoverySession) SealRecoveredDevice(ctx context.Context, id, deviceID string, signing ed25519.PrivateKey, receiving []byte, rights []cryptox.RecoveredDeviceRight) (ProtectedDAGOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.RecoveredPreparation != nil {
		return ProtectedDAGOperation{}, ErrDAGRecoveryState
	}
	return s.sealRecoveredDevice(ctx, id, deviceID, signing, receiving, DAGRecoveredSelectionIntent{SelectedRights: rights})
}

// B3 手机必须传明确已展示的基点并使用持久 preparation；不接自由签包。
func (s *DAGRecoverySession) SealRecoveredDeviceForIntent(ctx context.Context, id, deviceID string, signing ed25519.PrivateKey, receiving []byte, in DAGRecoveredSelectionIntent) (ProtectedDAGOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config.RecoveredPreparation == nil {
		return ProtectedDAGOperation{}, ErrDAGRecoveryState
	}
	return s.sealRecoveredDevice(ctx, id, deviceID, signing, receiving, in)
}
func (s *DAGRecoverySession) sealRecoveredDevice(ctx context.Context, id, deviceID string, signing ed25519.PrivateKey, receiving []byte, in DAGRecoveredSelectionIntent) (ProtectedDAGOperation, error) {
	rights := in.SelectedRights
	if e := s.live(); e != nil {
		return ProtectedDAGOperation{}, e
	}
	if s.pending != nil && !s.pending.Applied || s.transitionChallenge != nil || s.vault.RotationRequired || !enrollmentID.MatchString(id) || !enrollmentID.MatchString(deviceID) || len(signing) != ed25519.PrivateKeySize || len(rights) == 0 || len(rights) > 16 {
		return ProtectedDAGOperation{}, ErrDAGRecoveryState
	}
	x, e := ecdh.X25519().NewPrivateKey(receiving)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	if e = s.refresh(ctx); e != nil {
		return ProtectedDAGOperation{}, e
	}
	pub, recv := cryptox.EncodeBase64(signing.Public().(ed25519.PublicKey)), cryptox.EncodeBase64(x.PublicKey().Bytes())
	var preparation DAGRecoveredPreparation
	if s.config.RecoveredPreparation != nil {
		preparation, e = s.recoveredIntent(id, deviceID, pub, recv, in)
		if e != nil {
			return ProtectedDAGOperation{}, e
		}
		preparation, e = s.saveRecoveredIntent(preparation)
		if e != nil {
			return ProtectedDAGOperation{}, e
		}
		rights = preparation.SelectedRights
	}
	var c DAGDeviceChallenge
	if preparation.Challenge != nil {
		c = *preparation.Challenge
	} else if e = s.request(ctx, "POST", dagPath("recovered-device-challenges-v2"), s.token, map[string]string{"operationId": id, "deviceId": deviceID, "deviceSigningPublicKey": pub, "deviceReceivingPublicKey": recv}, &c); e != nil {
		if s.config.RecoveredPreparation != nil {
			return ProtectedDAGOperation{}, errors.Join(ErrDAGPreparationPending, e)
		}
		return ProtectedDAGOperation{}, e
	}
	if c.OperationID != id || c.DeviceID != deviceID || c.DeviceSigningPublicKey != pub || c.DeviceReceivingPublicKey != recv || c.AccountGeneration != strconv.FormatUint(s.config.AccountGeneration, 10) || c.ExpectedSequence != strconv.FormatUint(s.vault.Sequence, 10) || c.RestrictedSessionHash != digest([]byte(s.token)) || c.RecoveryGeneration != s.vault.RecoveryGeneration || c.RecoveryTransitionHash != s.vault.RecoveryHeadHash || c.ExpiresAt <= s.config.Now().Unix() || c.ExpiresAt > s.config.Now().Unix()+125 || !sameJSON(c.DependencyBundle, s.vault.DependencyBundle) {
		return ProtectedDAGOperation{}, cryptox.ErrInvalidWire
	}
	source, e := proofFromDAGSource(s.pin, c.DependencyBundle, c.IssuerEvidence)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	graph, e := cryptox.VerifyIssuerRecoveryDAG(s.pin, source)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	if s.config.RecoveredPreparation != nil && preparation.Phase == "intent" {
		preparation.Phase = "challenged"
		preparation.Challenge = &c
		if e = ValidateDAGRecoveredPreparation(preparation); e != nil {
			return ProtectedDAGOperation{}, e
		}
		if e = s.config.RecoveredPreparation.SaveRecoveredPreparation(preparation); e != nil {
			return ProtectedDAGOperation{}, e
		}
	}
	sub := cryptox.RecoveredDeviceSubmissionV2{CertificateVersion: "5", Capabilities: []string{cryptox.RecoveryDAGCapability}, SelectedRights: append([]cryptox.RecoveredDeviceRight(nil), rights...), Grants: []cryptox.SignedGrantWire{}, IssuerEvidence: c.IssuerEvidence, Envelopes: []cryptox.RecoveryEnvelope{}}
	sort.Slice(sub.SelectedRights, func(i, j int) bool { return sub.SelectedRights[i].EnvironmentID < sub.SelectedRights[j].EnvironmentID })
	seen := map[string]bool{}
	for i, row := range sub.SelectedRights {
		if seen[row.EnvironmentID] || row.Role != "ro" && row.Role != "rw" && row.Role != "admin" {
			return ProtectedDAGOperation{}, cryptox.ErrInvalidWire
		}
		seen[row.EnvironmentID] = true
		version := ""
		for _, env := range s.vault.Environments {
			if env.EnvironmentID == row.EnvironmentID {
				version = env.KeyVersion
			}
		}
		expiry, _ := strconv.ParseInt(row.ExpiresAt, 10, 64)
		if version == "" || row.KeyVersion != version || len(s.environmentKeys[row.EnvironmentID]) != 32 || expiry != 0 && expiry <= s.config.Now().Unix() {
			return ProtectedDAGOperation{}, cryptox.ErrInvalidWire
		}
		packet, e := cryptox.WrapEnvironmentKey(s.environmentKeys[row.EnvironmentID], cryptox.EnvelopeContext{AccountID: s.config.AccountID, AccountGeneration: c.AccountGeneration, EnvironmentID: row.EnvironmentID, KeyVersion: version, RecipientType: "device", RecipientID: deviceID, RecipientGeneration: "1", RecipientPublicKey: recv})
		if e != nil {
			return ProtectedDAGOperation{}, e
		}
		env := cryptox.RecoveryEnvelope{EnvironmentID: row.EnvironmentID, KeyVersion: version, Envelope: cryptox.EncodeBase64(packet)}
		sub.Envelopes = append(sub.Envelopes, env)
		g := cryptox.Grant{AccountID: s.config.AccountID, AccountGeneration: c.AccountGeneration, IssuerDeviceID: deviceID, SubjectDeviceID: deviceID, SubjectSigningPublicKey: pub, SubjectReceivingPublicKey: recv, EnvironmentID: row.EnvironmentID, KeyVersion: version, GrantGeneration: "1", Role: row.Role, ExpiresAt: row.ExpiresAt, IdempotencyKey: id + "-" + strconv.Itoa(i), Envelope: env.Envelope}
		signed, e := cryptox.SignGrant(g, signing)
		if e != nil {
			return ProtectedDAGOperation{}, e
		}
		sub.Grants = append(sub.Grants, cryptox.GrantToWire(signed))
	}
	rh, e := cryptox.RecoveredDeviceRightsHash(sub.SelectedRights)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	gh, e := cryptox.RecoveredDeviceGrantsHash(sub.Grants)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	eh, e := cryptox.RecoveredDeviceEnvelopesHash(sub.Envelopes)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	ih, e := sub.IssuerEvidence.Hash()
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	sub.Enrollment = cryptox.RecoveredDeviceEnrollmentV2{AccountID: s.config.AccountID, AccountGeneration: c.AccountGeneration, RecoveryGeneration: c.RecoveryGeneration, RecoveryTransitionHash: c.RecoveryTransitionHash, OperationID: id, ChallengeID: c.ChallengeID, Nonce: c.Nonce, ExpiresAt: strconv.FormatInt(c.ExpiresAt, 10), RestrictedSessionHash: c.RestrictedSessionHash, ExpectedSequence: c.ExpectedSequence, DeviceID: deviceID, DeviceSigningPublicKey: pub, DeviceReceivingPublicKey: recv, SelectedRightsHash: rh, GrantsHash: gh, IssuerEvidenceHash: ih, EnvelopesHash: eh}
	sub.RecoverySignature, e = cryptox.SignRecoveredDeviceByRecoveryV2(graph, sub, s.keys.SigningPrivate, s.config.Now())
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	sub.DeviceSignature, e = cryptox.SignRecoveredDeviceAfterHPKEV2(graph, sub, signing, receiving, s.config.Now())
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	command := cryptox.RecoveredDeviceCommandV2{Submission: sub, DependencyBundle: c.DependencyBundle}
	raw, e := json.Marshal(command)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	if _, e = cryptox.DecodeRecoveredDeviceCommandV2(raw); e != nil {
		return ProtectedDAGOperation{}, e
	}
	hash, e := cryptox.RecoveredDeviceReferenceHashV2(sub)
	if e != nil {
		return ProtectedDAGOperation{}, e
	}
	p := s.baseOperation("recovered-v2", id, hash)
	p.Recovered = &command
	if e = s.savePending(p); e != nil {
		return ProtectedDAGOperation{}, e
	}
	return cloneDAGOperation(p), nil
}
func (s *DAGRecoverySession) RetryRecoveredDevice(ctx context.Context) (DAGRecoveredResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var empty DAGRecoveredResult
	if e := s.live(); e != nil {
		return empty, e
	}
	if s.pending == nil || s.pending.Kind != "recovered-v2" || s.pending.Recovered == nil || s.vault.RotationRequired {
		return empty, ErrDAGRecoveryState
	}
	if e := s.checkPending(); e != nil {
		return empty, e
	}
	p := cloneDAGOperation(*s.pending)
	out, e := s.query(ctx, p)
	if e != nil {
		return empty, errors.Join(ErrEnrollmentPending, e)
	}
	sub := p.Recovered.Submission
	if !out.Accepted {
		expires, _ := strconv.ParseInt(sub.Enrollment.ExpiresAt, 10, 64)
		if sub.Enrollment.RestrictedSessionHash != digest([]byte(s.token)) || s.config.Now().Unix() >= expires {
			return empty, ErrDAGRecoveryState
		}
		p.Attempted = true
		if e = s.savePending(p); e != nil {
			return empty, e
		}
		if e = s.request(ctx, "POST", dagPath("recovered-devices-v2"), s.token, p.Recovered, &out); e != nil {
			return empty, errors.Join(ErrEnrollmentPending, e)
		}
		if e = expectedDAGReceipt(out, p.OperationID, p.ContentHash, sub.Enrollment.ExpectedSequence, true, false); e != nil {
			return empty, errors.Join(ErrEnrollmentPending, e)
		}
	}
	p.AcceptedSequence = out.Sequence
	if e = s.savePending(p); e != nil {
		return empty, errors.Join(ErrAcceptedNotApplied, e)
	}
	accepted := cryptox.AcceptedRecoveredDeviceV2{Submission: sub, Sequence: out.Sequence}
	bundle := p.Recovered.DependencyBundle
	bundle.Records = append(bundle.Records, cryptox.RecoveryDAGRecord{Kind: "recovered-v2", RecoveredV2: &accepted})
	if _, e = cryptox.VerifyRecoveryDependencyBundle(s.pin, bundle); e != nil {
		return empty, errors.Join(ErrAcceptedNotApplied, e)
	}
	evidence, e := buildRecoveredDAGEvidence(s.pin, bundle, accepted)
	if e != nil {
		return empty, errors.Join(ErrAcceptedNotApplied, e)
	}
	if e = s.refresh(ctx); e != nil {
		return empty, errors.Join(ErrAcceptedNotApplied, e)
	}
	p.Applied = true
	if e = s.savePending(p); e != nil {
		return empty, errors.Join(ErrAcceptedNotApplied, e)
	}
	return DAGRecoveredResult{Accepted: accepted, Evidence: evidence, Pin: s.pin}, nil
}

// PendingOperation返回已密封的公开原包，不包含受限token/seed。
func (s *DAGRecoverySession) PendingOperation() (ProtectedDAGOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return ProtectedDAGOperation{}, e
	}
	if s.pending == nil {
		return ProtectedDAGOperation{}, ErrDAGRecoveryState
	}
	return cloneDAGOperation(*s.pending), nil
}

// 新进程只确认已接受的原包。它保留当前受限session的RotationRequired，
// 不重生成nonce/种子、不替换原签包，也不能借旧收据解锁管理权限。
func (s *DAGRecoverySession) ResolveOriginalOperation(ctx context.Context) (DAGReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.live(); e != nil {
		return DAGReceipt{}, e
	}
	if e := s.checkPending(); e != nil {
		return DAGReceipt{}, e
	}
	p := cloneDAGOperation(*s.pending)
	out, e := s.query(ctx, p)
	if e != nil {
		return out, e
	}
	if !out.Accepted {
		return out, ErrEnrollmentPending
	}
	if e = s.refresh(ctx); e != nil {
		return out, e
	}
	found := false
	for _, record := range s.vault.DependencyBundle.Records {
		ref, e := record.Reference()
		if e != nil {
			return out, e
		}
		if ref.ReferenceHash != p.ContentHash {
			continue
		}
		if p.Transition != nil && record.TransitionV2 != nil {
			found = record.TransitionV2.Sequence == out.Sequence && sameJSON(record.TransitionV2.Submission, p.Transition.Submission)
		}
		if p.Recovered != nil && record.RecoveredV2 != nil {
			found = record.RecoveredV2.Sequence == out.Sequence && sameJSON(record.RecoveredV2.Submission, p.Recovered.Submission)
		}
	}
	if !found {
		return out, cryptox.ErrInvalidWire
	}
	p.AcceptedSequence = out.Sequence
	p.Applied = true
	if e = s.savePending(p); e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	return out, nil
}
