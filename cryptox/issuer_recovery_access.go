package cryptox

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
)

// VerifiedIssuerIdentity 仅表示完整来源图已验证的历史身份绑定。
// 它不证明设备当前活跃、持钥或具有任意环境的管理权限。
type VerifiedIssuerIdentity struct {
	DeviceID           string
	SigningPublicKey   string
	ReceivingPublicKey string
}

func (v *VerifiedIssuerRecoveryProof) VerifiedIdentity(deviceID string) (VerifiedIssuerIdentity, bool) {
	if v == nil || v.graph == nil {
		return VerifiedIssuerIdentity{}, false
	}
	id, ok := v.graph.identities[deviceID]
	if !ok {
		return VerifiedIssuerIdentity{}, false
	}
	return VerifiedIssuerIdentity{id.id, id.signing, id.receiving}, true
}

// VerifyEnvironmentOriginEvent 将数据事件和已验证控制图中的原 origin
// 签包精确关联；不能凭外层 before/公钥目录创建新的可信来源。
func (v *VerifiedIssuerRecoveryProof) VerifyEnvironmentOriginEvent(change SignedEnvironmentChange, origin SignedEnvironmentOrigin, authority SignedGrantWire) error {
	if v == nil || v.graph == nil {
		return ErrInvalidWire
	}
	return v.graph.VerifyEnvironmentOriginEvent(change, origin, authority)
}

// VerifyHistoricalMutationSource 用于服务器接受后的历史下发事件。
// 当前在线写入仍由服务器逐次核验会话/期限/撤销/代际和精确权限。
func (v *VerifiedIssuerRecoveryProof) VerifyHistoricalMutationSource(s SignedMutationWire, authority SignedGrantWire) error {
	if v == nil || v.graph == nil {
		return ErrInvalidWire
	}
	if e := v.VerifyHistoricalGrant(authority); e != nil {
		return e
	}
	m, g := s.Mutation, authority.Grant
	if m.AccountID != v.graph.accountID || m.AccountGeneration != v.graph.accountGeneration || g.AccountID != m.AccountID || g.AccountGeneration != m.AccountGeneration || g.SubjectDeviceID != m.DeviceID || g.EnvironmentID != m.EnvironmentID || g.KeyVersion != m.KeyVersion || g.GrantGeneration != m.GrantGeneration || (g.Role != "rw" && g.Role != "admin") {
		return ErrInvalidSignature
	}
	key, e := DecodeBase64(g.SubjectSigningPublicKey, 32, 32)
	if e != nil {
		return e
	}
	return VerifyMutation(s.SignedMutation(), ed25519.PublicKey(key))
}

// IssuerRecoveryCheckpoint 没有秘密；只有从完整已验证图取得后才能
// 与原回执/账本一起受保护保存。不能从服务器裸 metadata 构造信任。
type IssuerRecoveryCheckpoint struct {
	AccountID          string
	AccountGeneration  string
	RecoveryGeneration string
	SigningPublicKey   string
	ReceivingPublicKey string
	TransitionHead     string
	AcceptedSequence   uint64
}

func (v *VerifiedIssuerRecoveryProof) RecoveryCheckpoint() (IssuerRecoveryCheckpoint, error) {
	if v == nil || v.recovery == nil {
		return IssuerRecoveryCheckpoint{}, ErrInvalidWire
	}
	a := v.recovery
	return IssuerRecoveryCheckpoint{a.pin.AccountID, a.pin.AccountGeneration, a.Generation(), a.SigningPublicKey(), a.ReceivingPublicKey(), a.HeadHash(), a.sequence}, nil
}

// VerifyRecoveryCheckpointAdvance 使用原已验证对象的根 pin，而非候选图
// 的 root；新完整链必须保留已见链尾的同一摘要和接受序号。
// 它不取代普通权限/环境/数据检查点、scope、epoch 和原子保存检查。
func VerifyRecoveryCheckpointAdvance(prior *VerifiedIssuerRecoveryProof, candidate IssuerRecoveryProof) (*VerifiedIssuerRecoveryProof, error) {
	if prior == nil || prior.recovery == nil {
		return nil, ErrInvalidWire
	}
	next, e := VerifyIssuerRecoveryEvidence(prior.recovery.pin, candidate)
	if e != nil {
		return nil, e
	}
	checkpoint, e := prior.RecoveryCheckpoint()
	if e != nil {
		return nil, e
	}
	head, e := candidate.Initialization.Hash()
	if e != nil {
		return nil, e
	}
	found := head == checkpoint.TransitionHead && candidate.Initialization.Sequence == checkpoint.AcceptedSequence
	for _, r := range candidate.Transitions {
		h, e := RecoveryTransitionHash(r.Submission)
		if e != nil {
			return nil, e
		}
		if h == checkpoint.TransitionHead {
			t := r.Submission.Transition
			if r.Sequence != checkpoint.AcceptedSequence || t.NewRecoveryGeneration != checkpoint.RecoveryGeneration || t.NewRecoverySigningPublicKey != checkpoint.SigningPublicKey || t.NewRecoveryReceivingPublicKey != checkpoint.ReceivingPublicKey {
				return nil, ErrInvalidSignature
			}
			found = true
		}
	}
	if !found || next.recovery.sequence < checkpoint.AcceptedSequence {
		return nil, ErrInvalidSignature
	}
	return next, nil
}

// BuildRecoveredDeviceIssuerEvidence 只为已接受恢复设备构造本机来源图。
// 它不加载目录、不 apply 配置、不授当前会话，不替代 Boot/pull/final save。
// pin 必须来自恢复流程已经验证且受保护保存的原 root。
func BuildRecoveredDeviceIssuerEvidence(pin PinnedIssuerRoot, original OriginalInitialization, transitions []AcceptedRecoveryTransition, accepted AcceptedRecoveredDevice) (IssuerRecoveryProof, error) {
	var empty IssuerRecoveryProof
	authority, e := VerifyRecoveryInitialization(pin, original)
	if e != nil {
		return empty, e
	}
	ordered := append([]AcceptedRecoveryTransition(nil), transitions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	heads := map[string]*VerifiedRecoveryAuthority{authority.HeadHash(): authority}
	for _, r := range ordered {
		authority, e = VerifyAcceptedRecoveryTransition(authority, r)
		if e != nil {
			return empty, e
		}
		heads[authority.HeadHash()] = authority
	}
	point, known := heads[accepted.Submission.Enrollment.RecoveryTransitionHash]
	if !known {
		return empty, ErrInvalidSignature
	}
	device, e := VerifyAcceptedRecoveredDevice(point, accepted)
	if e != nil {
		return empty, e
	}
	source := accepted.Submission.IssuerEvidence
	root := source.TrustRoot
	if len(ordered) > 0 {
		root = ordered[len(ordered)-1].Submission.NewTrustRoot
	}
	proof := IssuerRecoveryProof{Profile: IssuerRecoveryProfile, AccountID: pin.AccountID, AccountGeneration: pin.AccountGeneration, TrustRoot: root, Initialization: original,
		Path: []IssuerRecoveryArchive{{Kind: "recovered", RecoveryEnrollmentHash: device.ReferenceHash()}}, Authorities: []IssuerRecoveryAuthority{}, Targets: []IssuerTarget{}, Origins: source.Origins,
		IdentityPaths: [][]IssuerRecoveryArchive{}, Transitions: ordered, RecoveredDevices: []AcceptedRecoveredDevice{accepted}}
	paired := func(path []IssuerEnrollment) []IssuerRecoveryArchive {
		out := make([]IssuerRecoveryArchive, 0, len(path))
		for _, n := range path {
			x := n
			out = append(out, IssuerRecoveryArchive{Kind: "paired", Enrollment: &x})
		}
		return out
	}
	if len(source.Path) > 0 {
		proof.IdentityPaths = append(proof.IdentityPaths, paired(source.Path))
	}
	for _, path := range source.IdentityPaths {
		proof.IdentityPaths = append(proof.IdentityPaths, paired(path))
	}
	for _, node := range source.Authorities {
		proof.Authorities = append(proof.Authorities, IssuerRecoveryAuthority{Grant: node.Grant, ParentHash: node.ParentHash, OriginHash: node.OriginHash, PreviousGrantHash: node.PreviousGrantHash})
	}
	for _, g := range accepted.Submission.Grants {
		h, e := IssuerAuthorityHash(g)
		if e != nil {
			return empty, e
		}
		proof.Authorities = append(proof.Authorities, IssuerRecoveryAuthority{Grant: g, RecoveryEnrollmentHash: device.ReferenceHash()})
		proof.Targets = append(proof.Targets, IssuerTarget{g.Grant.EnvironmentID, h})
	}
	// 深拷贝避免调用者随后更改原 journal 切片影响返回图。
	data, e := json.Marshal(proof)
	if e != nil {
		return empty, ErrInvalidWire
	}
	proof, e = DecodeIssuerRecoveryProof(data)
	if e != nil {
		return empty, e
	}
	if _, e = VerifyIssuerRecoveryEvidence(pin, proof); e != nil {
		return empty, e
	}
	return proof, nil
}
