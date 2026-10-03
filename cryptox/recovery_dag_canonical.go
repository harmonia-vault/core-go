package cryptox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

func dagHashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (p RecoverySourceView) CanonicalBytes() ([]byte, error) {
	if p.Profile != RecoverySourceViewProfile || validID(p.AccountID) != nil || validDecimal(p.AccountGeneration, true) != nil || !tokenHashPattern.MatchString(p.InitializationHash) || !tokenHashPattern.MatchString(p.RecoveryHeadHash) || p.Path == nil || p.Authorities == nil || p.Targets == nil || p.Origins == nil || p.IdentityPaths == nil || p.Dependencies == nil || len(p.Authorities) < 1 || len(p.Authorities) > MaxIssuerRecoveryRights || len(p.Targets) > 256 || len(p.Origins) > MaxIssuerOrigins || len(p.IdentityPaths) > MaxIssuerRecoveryPaths || len(p.Dependencies) > MaxRecoveryDAGNodes {
		return nil, ErrInvalidWire
	}
	root, e := p.TrustRoot.SigningBytes(p.AccountID, p.AccountGeneration)
	if e != nil {
		return nil, e
	}
	if _, e = DecodeBase64(p.TrustRoot.Signature, 64, 64); e != nil {
		return nil, e
	}
	paths, e := dagPathRows(p.Path)
	if e != nil {
		return nil, e
	}
	type branch struct {
		rows    [][]string
		encoded string
	}
	branches := make([]branch, 0, len(p.IdentityPaths))
	total := len(p.Path)
	for _, path := range p.IdentityPaths {
		if len(path) == 0 {
			return nil, ErrInvalidWire
		}
		total += len(path)
		r, e := dagPathRows(path)
		if e != nil {
			return nil, e
		}
		b, _ := json.Marshal(r)
		branches = append(branches, branch{r, string(b)})
	}
	if total > MaxIssuerRecoveryNodes {
		return nil, ErrInvalidWire
	}
	sort.Slice(branches, func(i, j int) bool { return branches[i].encoded < branches[j].encoded })
	branchRows := make([][][]string, 0, len(branches))
	for i, b := range branches {
		if i > 0 && branches[i-1].encoded == b.encoded {
			return nil, ErrInvalidWire
		}
		branchRows = append(branchRows, b.rows)
	}
	as := append([]IssuerRecoveryAuthority(nil), p.Authorities...)
	sort.Slice(as, func(i, j int) bool {
		a, b := as[i].Grant.Grant, as[j].Grant.Grant
		if a.EnvironmentID != b.EnvironmentID {
			return a.EnvironmentID < b.EnvironmentID
		}
		if a.SubjectDeviceID != b.SubjectDeviceID {
			return a.SubjectDeviceID < b.SubjectDeviceID
		}
		x, _ := strconv.ParseUint(a.GrantGeneration, 10, 64)
		y, _ := strconv.ParseUint(b.GrantGeneration, 10, 64)
		return x < y
	})
	rows := make([][]string, 0, len(as))
	seen := map[string]bool{}
	for _, a := range as {
		g := a.Grant.Grant
		b, e := g.SigningBytes()
		if e != nil {
			return nil, e
		}
		if g.Role != "ro" && g.Role != "rw" && g.Role != "admin" {
			return nil, ErrInvalidWire
		}
		for _, h := range []string{a.ParentHash, a.OriginHash, a.PreviousGrantHash, a.RecoveryEnrollmentHash} {
			if h != "" && !tokenHashPattern.MatchString(h) {
				return nil, ErrInvalidWire
			}
		}
		if _, e = IssuerAuthorityHash(a.Grant); e != nil {
			return nil, e
		}
		id := g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration
		if seen[id] {
			return nil, ErrInvalidWire
		}
		seen[id] = true
		rows = append(rows, []string{g.EnvironmentID, g.SubjectDeviceID, g.GrantGeneration, EncodeBase64(b), a.Grant.Signature, a.ParentHash, a.OriginHash, a.PreviousGrantHash, a.RecoveryEnrollmentHash})
	}
	ts := append([]IssuerTarget(nil), p.Targets...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].EnvironmentID < ts[j].EnvironmentID })
	targets := make([][]string, 0, len(ts))
	for i, t := range ts {
		if validID(t.EnvironmentID) != nil || !tokenHashPattern.MatchString(t.AuthorityHash) || (i > 0 && ts[i-1].EnvironmentID == t.EnvironmentID) {
			return nil, ErrInvalidWire
		}
		targets = append(targets, []string{t.EnvironmentID, t.AuthorityHash})
	}
	origins := make([][]string, 0, len(p.Origins))
	for _, s := range p.Origins {
		h, e := EnvironmentOriginHash(s)
		if e != nil {
			return nil, e
		}
		b, _ := s.Origin.SigningBytes()
		origins = append(origins, []string{h, EncodeBase64(b), s.Signature})
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i][0] < origins[j][0] })
	for i := 1; i < len(origins); i++ {
		if origins[i-1][0] == origins[i][0] {
			return nil, ErrInvalidWire
		}
	}

	deps := append([]RecoveryDependency(nil), p.Dependencies...)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Kind != deps[j].Kind {
			return deps[i].Kind < deps[j].Kind
		}
		return deps[i].ReferenceHash < deps[j].ReferenceHash
	})
	dependencyRows := make([][]string, 0, len(deps))
	seenDeps := map[string]bool{}
	for _, d := range deps {
		if !validDAGKind(d.Kind) || !tokenHashPattern.MatchString(d.ReferenceHash) || seenDeps[d.ReferenceHash] {
			return nil, ErrInvalidWire
		}
		seenDeps[d.ReferenceHash] = true
		dependencyRows = append(dependencyRows, []string{d.Kind, d.ReferenceHash})
	}
	b, e := json.Marshal([]any{p.Profile, p.AccountID, p.AccountGeneration, p.InitializationHash, []string{EncodeBase64(root), p.TrustRoot.Signature}, p.RecoveryHeadHash, paths, rows, targets, origins, branchRows, dependencyRows})
	if e != nil || len(b) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	return b, nil
}
