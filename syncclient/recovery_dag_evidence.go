package syncclient

import (
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
)

func cloneDAGSource(s cryptox.RecoverySource) cryptox.RecoverySource {
	b, _ := json.Marshal(s)
	var out cryptox.RecoverySource
	_ = json.Unmarshal(b, &out)
	return out
}
func directDAGReferences(s cryptox.RecoverySource, initial string) ([]string, error) {
	if _, e := s.CanonicalBytes(); e != nil {
		return nil, e
	}
	if s.Kind == "proof2" {
		return []string{}, nil
	}
	v := s.View
	set := map[string]bool{}
	if v.RecoveryHeadHash != initial {
		set[v.RecoveryHeadHash] = true
	}
	for _, path := range append([][]cryptox.IssuerRecoveryArchive{v.Path}, v.IdentityPaths...) {
		for _, n := range path {
			if n.Kind == "recovered" {
				set[n.RecoveryEnrollmentHash] = true
			}
		}
	}
	for _, n := range v.Authorities {
		if n.RecoveryEnrollmentHash != "" {
			set[n.RecoveryEnrollmentHash] = true
		}
	}
	out := []string{}
	for h := range set {
		out = append(out, h)
	}
	return out, nil
}

// 这里只选择公开记录闭包；所有签名/边/接受序号仍由成熟DAG验证器完整复验。
func proofFromDAGSource(pin cryptox.PinnedIssuerRoot, bundle cryptox.RecoveryDependencyBundle, source cryptox.RecoverySource) (cryptox.IssuerRecoveryDAG, error) {
	var empty cryptox.IssuerRecoveryDAG
	if _, e := cryptox.VerifyRecoveryDependencyBundle(pin, bundle); e != nil {
		return empty, e
	}
	initial, e := bundle.Initialization.Hash()
	if e != nil {
		return empty, e
	}
	refs, e := directDAGReferences(source, initial)
	if e != nil {
		return empty, e
	}
	rows := map[string]cryptox.RecoveryDAGRecord{}
	for _, r := range bundle.Records {
		ref, e := r.Reference()
		if e != nil {
			return empty, e
		}
		rows[ref.ReferenceHash] = r
	}
	needed := map[string]bool{}
	for len(refs) > 0 {
		h := refs[len(refs)-1]
		refs = refs[:len(refs)-1]
		if needed[h] {
			continue
		}
		r, ok := rows[h]
		if !ok {
			return empty, cryptox.ErrInvalidWire
		}
		needed[h] = true
		var parent string
		var s *cryptox.RecoverySource
		switch r.Kind {
		case "transition-v1":
			t := r.TransitionV1.Submission
			parent = t.Transition.PreviousTransitionHash
			if t.IssuerEvidence != nil {
				s = &cryptox.RecoverySource{Kind: "proof2", Proof: t.IssuerEvidence}
			}
		case "recovered-v1":
			t := r.RecoveredV1.Submission
			parent = t.Enrollment.RecoveryTransitionHash
			s = &cryptox.RecoverySource{Kind: "proof2", Proof: &t.IssuerEvidence}
		case "transition-v2":
			t := r.TransitionV2.Submission
			parent = t.Transition.PreviousTransitionHash
			s = t.IssuerEvidence
		case "recovered-v2":
			t := r.RecoveredV2.Submission
			parent = t.Enrollment.RecoveryTransitionHash
			s = &t.IssuerEvidence
		default:
			return empty, cryptox.ErrInvalidWire
		}
		if parent != initial {
			refs = append(refs, parent)
		}
		if s != nil {
			more, e := directDAGReferences(*s, initial)
			if e != nil {
				return empty, e
			}
			refs = append(refs, more...)
		}
	}
	p := cryptox.IssuerRecoveryDAG{Profile: cryptox.IssuerRecoveryDAGProfile, AccountID: pin.AccountID, AccountGeneration: pin.AccountGeneration, Initialization: bundle.Initialization, Source: cloneDAGSource(source), Records: []cryptox.RecoveryDAGRecord{}}
	for h := range needed {
		p.Records = append(p.Records, rows[h])
	}
	normalizeDAG(&p)
	if _, e = cryptox.VerifyIssuerRecoveryDAG(pin, p); e != nil {
		return empty, e
	}
	return p, nil
}
func buildRecoveredDAGEvidence(pin cryptox.PinnedIssuerRoot, bundle cryptox.RecoveryDependencyBundle, accepted cryptox.AcceptedRecoveredDeviceV2) (cryptox.IssuerRecoveryDAG, error) {
	p := cryptox.IssuerRecoveryDAG{Initialization: bundle.Initialization, AccountID: pin.AccountID, AccountGeneration: pin.AccountGeneration, Source: cloneDAGSource(accepted.Submission.IssuerEvidence), Records: []cryptox.RecoveryDAGRecord{}}
	v, e := dagView(&p)
	if e != nil {
		return p, e
	}
	h, e := cryptox.RecoveredDeviceReferenceHashV2(accepted.Submission)
	if e != nil {
		return p, e
	}
	if len(v.Path) > 0 {
		v.IdentityPaths = append(v.IdentityPaths, v.Path)
	}
	v.Path = []cryptox.IssuerRecoveryArchive{{Kind: "recovered", RecoveryEnrollmentHash: h}}
	v.Targets = []cryptox.IssuerTarget{}
	for _, g := range accepted.Submission.Grants {
		gh, e := cryptox.IssuerAuthorityHash(g)
		if e != nil {
			return p, e
		}
		v.Authorities = append(v.Authorities, cryptox.IssuerRecoveryAuthority{Grant: g, RecoveryEnrollmentHash: h})
		v.Targets = append(v.Targets, cryptox.IssuerTarget{EnvironmentID: g.Grant.EnvironmentID, AuthorityHash: gh})
	}
	v.Dependencies = append(v.Dependencies, cryptox.RecoveryDependency{Kind: "recovered-v2", ReferenceHash: h})
	normalizeDAG(&p)
	return proofFromDAGSource(pin, bundle, p.Source)
}
