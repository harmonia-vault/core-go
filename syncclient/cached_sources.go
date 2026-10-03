package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 缓存来源是旧数据的已验读授权；当前权限仍只取保护账本的精确 target。
// 路径只引用全图已验的签授权，不能将服务端数组提示直接当授权。
type cachedSourceLedger struct {
	proof   verifiedAuthorityGraph
	rights  map[string]cryptox.IssuerAuthorityV2
	origins map[string]cryptox.SignedEnvironmentOrigin
	targets map[string]string
}

func newCachedSourceLedger(p cryptox.IssuerProofV2, proof verifiedAuthorityGraph) (*cachedSourceLedger, error) {
	if proof == nil {
		return nil, cryptox.ErrInvalidSignature
	}
	l := &cachedSourceLedger{proof: proof, rights: map[string]cryptox.IssuerAuthorityV2{}, origins: map[string]cryptox.SignedEnvironmentOrigin{}, targets: map[string]string{}}
	for _, n := range p.Authorities {
		h, e := cryptox.IssuerAuthorityHash(n.Grant)
		if e != nil {
			return nil, e
		}
		l.rights[h] = n
	}
	for _, o := range p.Origins {
		h, e := cryptox.EnvironmentOriginHash(o)
		if e != nil {
			return nil, e
		}
		l.origins[h] = o
	}
	for _, t := range p.Targets {
		l.targets[t.EnvironmentID] = t.AuthorityHash
	}
	return l, nil
}
func (v *PinnedVerifier) boundCachedGrant(l *cachedSourceLedger, h, id string) (cryptox.SignedGrantWire, error) {
	s, ok := l.proof.Authority(h)
	g := s.Grant
	if !ok || g.AccountID != v.trust.AccountID || g.AccountGeneration != strconv.FormatUint(v.trust.AccountGeneration, 10) || g.EnvironmentID != id || g.SubjectDeviceID != v.trust.DeviceID || g.SubjectSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || g.SubjectReceivingPublicKey != v.receivingPublicKey || (g.Role != "ro" && g.Role != "rw" && g.Role != "admin") || l.proof.VerifyHistoricalGrant(s) != nil {
		return s, cryptox.ErrInvalidSignature
	}
	return s, nil
}
func cacheGrantRole(g cryptox.Grant) localstate.Role {
	if g.Role == "admin" {
		return localstate.Admin
	}
	if g.Role == "rw" {
		return localstate.ReadWrite
	}
	return localstate.ReadOnly
}
func cacheGrantExpiry(g cryptox.Grant) (*time.Time, error) {
	n, e := strconv.ParseInt(g.ExpiresAt, 10, 64)
	if e != nil || n < 0 {
		return nil, cryptox.ErrInvalidWire
	}
	if n == 0 {
		return nil, nil
	}
	t := time.Unix(n, 0)
	return &t, nil
}
func smallerExpiry(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil || a.Before(*b) {
		return a
	}
	return b
}
func exactExpiry(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}

// 每个新段必须实际连续：同 KV 的下一 grant generation，或由 exact
// before/after 和 PreviousGrantHash 绑定的下一 KV/下一 generation。
func (v *PinnedVerifier) cachedSourceEdge(l *cachedSourceLedger, from, to, id string) error {
	a, e := v.boundCachedGrant(l, from, id)
	if e != nil {
		return e
	}
	b, e := v.boundCachedGrant(l, to, id)
	if e != nil {
		return e
	}
	ag, e := parsePositive(a.Grant.GrantGeneration)
	if e != nil {
		return e
	}
	bg, e := parsePositive(b.Grant.GrantGeneration)
	if e != nil || ag == ^uint64(0) || bg != ag+1 {
		return cryptox.ErrInvalidWire
	}
	if a.Grant.KeyVersion == b.Grant.KeyVersion {
		return nil
	}
	ak, e := parsePositive(a.Grant.KeyVersion)
	if e != nil {
		return e
	}
	bk, e := parsePositive(b.Grant.KeyVersion)
	if e != nil || ak == ^uint64(0) || bk != ak+1 {
		return cryptox.ErrInvalidWire
	}
	n, ok := l.rights[to]
	if !ok || n.PreviousGrantHash != from || n.OriginHash == "" {
		return cryptox.ErrInvalidSignature
	}
	o, ok := l.origins[n.OriginHash]
	if !ok || o.Origin.Operation != "rotate" || o.Origin.EnvironmentID != id || o.Origin.PreviousKeyVersion != a.Grant.KeyVersion || o.Origin.KeyVersion != b.Grant.KeyVersion {
		return cryptox.ErrInvalidSignature
	}
	before, e := cryptox.EnvironmentRights([]cryptox.SignedGrantWire{a})
	if e != nil {
		return e
	}
	after, e := cryptox.EnvironmentRights([]cryptox.SignedGrantWire{b})
	if e != nil {
		return e
	}
	for i, r := range o.Origin.Before {
		if r.GrantHash == from && i < len(o.Origin.After) && r == before[0] && o.Origin.After[i] == after[0] && r.Role == after[0].Role && r.ExpiresAt == after[0].ExpiresAt {
			return nil
		}
	}
	return cryptox.ErrInvalidSignature
}
func (v *PinnedVerifier) extendCachedPath(l *cachedSourceLedger, from, to, id string) ([]string, error) {
	visited := map[string]bool{}
	var walk func(string) ([]string, error)
	walk = func(h string) ([]string, error) {
		if h == from {
			return []string{from}, nil
		}
		if visited[h] || len(visited) >= cryptox.MaxIssuerRightsV2 {
			return nil, cryptox.ErrInvalidWire
		}
		visited[h] = true
		target, e := v.boundCachedGrant(l, h, id)
		if e != nil {
			return nil, e
		}
		node, ok := l.rights[h]
		if !ok {
			return nil, cryptox.ErrInvalidWire
		}
		var prior string
		if node.OriginHash != "" {
			prior = node.PreviousGrantHash
		} else {
			generation, e := parsePositive(target.Grant.GrantGeneration)
			if e != nil || generation <= 1 {
				return nil, cryptox.ErrInvalidWire
			}
			// 不猜目录公钥、不跨 generation 缺口；同 generation 多个 signed包也拒绝。
			for candidate, n := range l.rights {
				g := n.Grant.Grant
				if g.EnvironmentID == id && g.KeyVersion == target.Grant.KeyVersion && g.GrantGeneration == strconv.FormatUint(generation-1, 10) && g.SubjectDeviceID == v.trust.DeviceID && g.SubjectSigningPublicKey == cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) && g.SubjectReceivingPublicKey == v.receivingPublicKey && g.Role != "none" {
					if prior != "" && prior != candidate {
						return nil, cryptox.ErrInvalidWire
					}
					prior = candidate
				}
			}
		}
		if prior == "" {
			return nil, cryptox.ErrInvalidSignature
		}
		if e = v.cachedSourceEdge(l, prior, h, id); e != nil {
			return nil, e
		}
		path, e := walk(prior)
		if e != nil {
			return nil, e
		}
		return append(path, h), nil
	}
	return walk(to)
}
func (v *PinnedVerifier) cachedSourceBounds(l *cachedSourceLedger, env localstate.Environment) (localstate.Role, *time.Time, error) {
	source := env.Source
	if source == nil || len(source.AuthorizationPath) == 0 || len(source.AuthorizationPath) > cryptox.MaxIssuerRightsV2 || source.AuthorizationPath[0] != source.AuthorityHash {
		return "", nil, cryptox.ErrInvalidWire
	}
	anchor, e := v.boundCachedGrant(l, source.AuthorityHash, env.ID)
	if e != nil {
		return "", nil, e
	}
	b, e := anchor.Grant.SigningBytes()
	if e != nil || source.Fingerprint != digest(b) || anchor.Grant.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || anchor.Grant.GrantGeneration != strconv.FormatUint(env.GrantGeneration, 10) {
		return "", nil, errors.New("cached data source fingerprint/version mismatch")
	}
	role := cacheGrantRole(anchor.Grant)
	expiry, e := cacheGrantExpiry(anchor.Grant)
	if e != nil {
		return "", nil, e
	}
	seen := map[string]bool{}
	for i, h := range source.AuthorizationPath {
		if seen[h] {
			return "", nil, cryptox.ErrInvalidWire
		}
		seen[h] = true
		s, e := v.boundCachedGrant(l, h, env.ID)
		if e != nil {
			return "", nil, e
		}
		if i > 0 {
			if e = v.cachedSourceEdge(l, source.AuthorizationPath[i-1], h, env.ID); e != nil {
				return "", nil, e
			}
		}
		r := cacheGrantRole(s.Grant)
		if issuerCacheRoleRank(r) < issuerCacheRoleRank(role) {
			role = r
		}
		x, e := cacheGrantExpiry(s.Grant)
		if e != nil {
			return "", nil, e
		}
		expiry = smallerExpiry(expiry, x)
	}
	return role, expiry, nil
}
func (v *PinnedVerifier) validateSourceTarget(previous localstate.CloudSnapshot, env localstate.Environment, l *cachedSourceLedger) error {
	role, expiry, e := v.cachedSourceBounds(l, env)
	if e != nil {
		return e
	}
	tail := env.Source.AuthorizationPath[len(env.Source.AuthorizationPath)-1]
	if tail != l.targets[env.ID] {
		return errors.New("cached source path does not end at the exact current authorization")
	}
	for _, h := range env.Source.AuthorizationPath {
		n := l.rights[h]
		if n.OriginHash != "" {
			o := l.origins[n.OriginHash].Origin
			seq, e := strconv.ParseUint(o.ExpectedSequence, 10, 64)
			checkpoint := previous.AuthorizationSequence
			if checkpoint < previous.Sequence {
				checkpoint = previous.Sequence
			}
			if e != nil || seq >= checkpoint {
				return cryptox.ErrInvalidWire
			}
		}
	}
	current, e := v.boundCachedGrant(l, tail, env.ID)
	if e != nil {
		return e
	}
	g := current.Grant
	b, e := g.SigningBytes()
	gg, e2 := parsePositive(g.GrantGeneration)
	if e != nil || e2 != nil || previous.GrantCheckpoints[env.ID] != gg || previous.GrantFingerprints[env.ID] != digest(b) || l.proof.VerifyTarget(current, v.trust.DeviceID, cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey), v.receivingPublicKey) != nil {
		return errors.New("current authorization checkpoint/fingerprint mismatch")
	}
	if previous.DeletedEnvironments[env.ID] != 0 || issuerCacheRoleRank(env.Role) == 0 || issuerCacheRoleRank(env.Role) > issuerCacheRoleRank(role) || env.ExpiresAt != nil && env.ExpiresAt.Nanosecond() != 0 || expiry != nil && (env.ExpiresAt == nil || env.ExpiresAt.After(*expiry)) {
		return errors.New("cached permission exceeds signed source/current ceilings")
	}
	// 未暂停投影的完整数据必须与当前 grant 精确一致。
	if previous.AuthorizationSequence <= previous.Sequence && (len(env.Source.AuthorizationPath) != 1 || env.Role != role || !exactExpiry(env.ExpiresAt, expiry)) {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func (v *PinnedVerifier) sourceForPrevious(old localstate.Environment, previous localstate.CloudSnapshot) (*localstate.EnvironmentSource, error) {
	if old.Source != nil {
		s := *old.Source
		s.AuthorizationPath = append([]string(nil), s.AuthorizationPath...)
		return &s, nil
	}
	if v.initialRecoveryEvidence != nil {
		return nil, cryptox.ErrInvalidWire
	}
	p := *v.initialEvidence
	if len(previous.IssuerEvidence) > 0 {
		var e error
		p, e = decodeEvidence(previous.IssuerEvidence)
		if e != nil {
			return nil, e
		}
	}
	var h string
	for _, t := range p.Targets {
		if t.EnvironmentID == old.ID {
			h = t.AuthorityHash
		}
	}
	proof, e := cryptox.VerifyIssuerEvidenceV2(*v.evidenceRoot, p, v.genesisAuthorities...)
	if e != nil {
		return nil, e
	}
	l, e := newCachedSourceLedger(p, proof)
	if e != nil {
		return nil, e
	}
	g, e := v.boundCachedGrant(l, h, old.ID)
	if e != nil {
		return nil, e
	}
	wire, e := g.Grant.SigningBytes()
	expiry, e2 := cacheGrantExpiry(g.Grant)
	if e != nil || e2 != nil || g.Grant.KeyVersion != strconv.FormatUint(old.KeyVersion, 10) || g.Grant.GrantGeneration != strconv.FormatUint(old.GrantGeneration, 10) || previous.GrantCheckpoints[old.ID] != old.GrantGeneration || previous.GrantFingerprints[old.ID] != digest(wire) || old.Role != cacheGrantRole(g.Grant) || !exactExpiry(old.ExpiresAt, expiry) {
		return nil, errors.New("legacy cached source requires exact same KV/generation/fingerprint/permission")
	}
	return &localstate.EnvironmentSource{AuthorityHash: h, Fingerprint: digest(wire), AuthorizationPath: []string{h}}, nil
}
func (v *PinnedVerifier) retainCachedEnvironment(ctx context.Context, old localstate.Environment, previous localstate.CloudSnapshot, pull Pull, signed SignedGrant, evidence json.RawMessage) (localstate.Environment, error) {
	if e := ctx.Err(); e != nil {
		return old, e
	}
	l, e := v.cachedLedger(evidence)
	if e != nil {
		return old, e
	}
	source, e := v.sourceForPrevious(old, previous)
	if e != nil {
		return old, e
	}
	old.Source = source
	to, e := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: signed.Grant, Signature: signed.Signature})
	if e != nil {
		return old, e
	}
	from := source.AuthorizationPath[len(source.AuthorizationPath)-1]
	path, e := v.extendCachedPath(l, from, to, old.ID)
	if e != nil {
		return old, e
	}
	source.AuthorizationPath = append(source.AuthorizationPath, path[1:]...)
	if len(source.AuthorizationPath) > cryptox.MaxIssuerRightsV2 {
		return old, cryptox.ErrInvalidWire
	}
	for _, h := range path[1:] {
		n := l.rights[h]
		if n.OriginHash != "" {
			o := l.origins[n.OriginHash].Origin
			seq, e := strconv.ParseUint(o.ExpectedSequence, 10, 64)
			if e != nil || seq >= pull.Sequence {
				return old, cryptox.ErrInvalidWire
			}
		}
	}
	role, expiry, e := v.cachedSourceBounds(l, old)
	if e != nil {
		return old, e
	}
	if issuerCacheRoleRank(role) < issuerCacheRoleRank(old.Role) {
		old.Role = role
	}
	old.ExpiresAt = smallerExpiry(old.ExpiresAt, expiry)
	old.Values = copyMap(old.Values)
	return old, nil
}
func (v *PinnedVerifier) initializeCachedSources(out *localstate.CloudSnapshot, evidence json.RawMessage) error {
	if v.evidenceRoot == nil {
		return nil
	}
	l, e := v.cachedLedger(evidence)
	if e != nil {
		return e
	}
	for id, env := range out.Environments {
		h := l.targets[id]
		g, e := v.boundCachedGrant(l, h, id)
		if e != nil {
			return e
		}
		wire, e := g.Grant.SigningBytes()
		if e != nil {
			return e
		}
		env.Source = &localstate.EnvironmentSource{AuthorityHash: h, Fingerprint: digest(wire), AuthorizationPath: []string{h}}
		out.Environments[id] = env
		if e = v.validateSourceTarget(*out, env, l); e != nil {
			return e
		}
	}
	return nil
}
