package cryptox

import (
	"encoding/json"
	"sort"
	"strconv"
	"sync"
)

// VerifiedRecoveryDAG 只保存已经验证的公开材料；不含恢复种子或私钥。
type VerifiedRecoveryDAG struct {
	pin                PinnedIssuerRoot
	original           OriginalInitialization
	initializationHash string
	current            *VerifiedRecoveryAuthority
	heads              map[string]*VerifiedRecoveryAuthority
	records            map[string]RecoveryDAGRecord
	sequences          map[string]uint64
	dependencies       map[string][]RecoveryDependency
	recovered          map[string]*VerifiedRecoveredDevice
	recoveredGrants    map[string][]SignedGrantWire
	publicOwners       map[string]string
	identities         map[string]issuerIdentity
	sourceMemo         map[string]*VerifiedIssuerProofV2
	sourceMutex        sync.Mutex
	graph              *VerifiedIssuerProofV2
	lastSequence       uint64
	edges              int
}

func sourceRoot(s RecoverySource) (TrustRoot, error) {
	if _, e := s.CanonicalBytes(); e != nil {
		return TrustRoot{}, e
	}

	return s.View.TrustRoot, nil
}
func (d *VerifiedRecoveryDAG) addIdentity(id issuerIdentity) error {
	if validatePublicPair(id.signing, id.receiving) != nil {
		return ErrInvalidWire
	}
	if old, ok := d.identities[id.id]; ok && old != id {
		return ErrInvalidSignature
	}
	for _, key := range []string{id.signing, id.receiving} {
		if old := d.publicOwners[key]; old != "" && old != "device/"+id.id {
			return ErrInvalidSignature
		}
	}
	d.identities[id.id] = id
	d.publicOwners[id.signing] = "device/" + id.id
	d.publicOwners[id.receiving] = "device/" + id.id
	return nil
}
func (d *VerifiedRecoveryDAG) mergeGraph(g *VerifiedIssuerProofV2) error {
	if g == nil {
		return nil
	}
	for _, id := range g.identities {
		if e := d.addIdentity(id); e != nil {
			return e
		}
	}
	return nil
}
func (d *VerifiedRecoveryDAG) addRecoveryKeys(v *VerifiedRecoveryAuthority) error {
	for key := range v.usedRecoveryKeys {
		if old := d.publicOwners[key]; old != "" && old != "recovery" {
			return ErrInvalidSignature
		}
		d.publicOwners[key] = "recovery"
	}
	return nil
}
func sourceReferenceHashes(s RecoverySource, initial string) (map[string]bool, error) {
	if _, e := s.CanonicalBytes(); e != nil {
		return nil, e
	}
	out := map[string]bool{}

	v := s.View
	if v.InitializationHash != initial {
		return nil, ErrInvalidSignature
	}
	if v.RecoveryHeadHash != initial {
		out[v.RecoveryHeadHash] = true
	}
	for _, path := range append([][]IssuerRecoveryArchive{v.Path}, v.IdentityPaths...) {
		for _, n := range path {
			if n.Kind == "recovered" {
				out[n.RecoveryEnrollmentHash] = true
			}
		}
	}
	for _, a := range v.Authorities {
		if a.RecoveryEnrollmentHash != "" {
			out[a.RecoveryEnrollmentHash] = true
		}
	}
	return out, nil
}
func (d *VerifiedRecoveryDAG) sourceDependencies(s RecoverySource, cutoff uint64) ([]RecoveryDependency, error) {
	hashes, e := sourceReferenceHashes(s, d.initializationHash)
	if e != nil {
		return nil, e
	}
	out := make([]RecoveryDependency, 0, len(hashes))
	for h := range hashes {
		r, ok := d.records[h]
		if !ok || d.sequences[h] > cutoff {
			return nil, ErrInvalidWire
		}
		out = append(out, RecoveryDependency{r.Kind, h})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ReferenceHash < out[j].ReferenceHash
	})
	if s.Kind == "proof3" {
		provided := map[string]string{}
		for _, dep := range s.View.Dependencies {
			if _, ok := provided[dep.ReferenceHash]; ok {
				return nil, ErrInvalidWire
			}
			provided[dep.ReferenceHash] = dep.Kind
		}
		if len(provided) != len(out) {
			return nil, ErrInvalidWire
		}
		for _, dep := range out {
			if provided[dep.ReferenceHash] != dep.Kind {
				return nil, ErrInvalidWire
			}
		}
	}
	return out, nil
}
func (d *VerifiedRecoveryDAG) sourceGraph(s RecoverySource, cutoff uint64) (*VerifiedIssuerProofV2, error) {
	if d == nil || cutoff > 9007199254740991 {
		return nil, ErrInvalidWire
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	var isolated RecoverySource
	if e = strictDAGDecode(raw, &isolated); e != nil {
		return nil, e
	}
	s = isolated
	deps, e := d.sourceDependencies(s, cutoff)
	if e != nil {
		return nil, e
	}
	h, e := s.Hash()
	if e != nil {
		return nil, e
	}

	v := s.View
	if v.AccountID != d.pin.AccountID || v.AccountGeneration != d.pin.AccountGeneration || v.RecoveryHeadHash != d.current.head {
		return nil, ErrInvalidSignature
	}
	head, ok := d.heads[v.RecoveryHeadHash]
	if !ok || head.sequence > cutoff || !recoveryRootMatches(d.pin, v.TrustRoot) || v.TrustRoot.RecoveryGeneration != head.recoveryGeneration || v.TrustRoot.RecoverySigningPublicKey != head.signingPublic || v.TrustRoot.RecoveryReceivingPublicKey != head.receivingPublic {
		return nil, ErrInvalidSignature
	}
	pub, e := DecodeBase64(head.signingPublic, 32, 32)
	if e != nil {
		return nil, e
	}
	if e = VerifyTrustRoot(v.AccountID, v.AccountGeneration, v.TrustRoot, pub); e != nil {
		return nil, e
	}
	for _, origin := range v.Origins {
		n, e := strconv.ParseUint(origin.Origin.ExpectedSequence, 10, 64)
		if e != nil || n >= cutoff {
			return nil, ErrInvalidWire
		}
	}
	d.sourceMutex.Lock()
	memo := d.sourceMemo[h]
	d.sourceMutex.Unlock()
	if memo != nil {
		return memo, nil
	}
	recovered := map[string]*VerifiedRecoveredDevice{}
	grants := [][]SignedGrantWire{}
	for _, dep := range deps {
		if r := d.recovered[dep.ReferenceHash]; r != nil {
			recovered[dep.ReferenceHash] = r
			grants = append(grants, d.recoveredGrants[dep.ReferenceHash])
		}
	}
	p := IssuerRecoveryProof{AccountID: v.AccountID, AccountGeneration: v.AccountGeneration, Path: v.Path, Authorities: v.Authorities, Targets: v.Targets, Origins: v.Origins, IdentityPaths: v.IdentityPaths}
	result, e := verifyRecoverySourceGraph(d.pin, head, p, recovered, grants, dagArchiveBytes)
	if e != nil {
		return nil, e
	}
	for _, id := range result.graph.identities {
		for _, pub := range []string{id.signing, id.receiving} {
			if owner := d.publicOwners[pub]; owner != "" && owner != "device/"+id.id {
				return nil, ErrInvalidSignature
			}
		}
	}
	d.sourceMutex.Lock()
	d.sourceMemo[h] = result.graph
	d.sourceMutex.Unlock()
	return result.graph, nil
}
func (d *VerifiedRecoveryDAG) recordDependencies(r RecoveryDAGRecord, cutoff uint64) ([]RecoveryDependency, error) {
	need := map[string]RecoveryDependency{}
	var parent string
	var source *RecoverySource
	switch r.Kind {
	case "transition-v2":
		parent = r.TransitionV2.Submission.Transition.PreviousTransitionHash
		source = r.TransitionV2.Submission.IssuerEvidence
	case "recovered-v2":
		parent = r.RecoveredV2.Submission.Enrollment.RecoveryTransitionHash
		source = &r.RecoveredV2.Submission.IssuerEvidence
	default:
		return nil, ErrInvalidWire
	}
	if parent != d.initializationHash {
		node, ok := d.records[parent]
		if !ok || d.sequences[parent] > cutoff || node.Kind != "transition-v2" {
			return nil, ErrInvalidWire
		}
		need[parent] = RecoveryDependency{node.Kind, parent}
	}
	if source != nil {
		deps, e := d.sourceDependencies(*source, cutoff)
		if e != nil {
			return nil, e
		}
		for _, dep := range deps {
			need[dep.ReferenceHash] = dep
		}
	}
	out := make([]RecoveryDependency, 0, len(need))
	for _, dep := range need {
		out = append(out, dep)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ReferenceHash < out[j].ReferenceHash
	})
	return out, nil
}
func VerifyRecoveryDependencyBundle(pin PinnedIssuerRoot, bundle RecoveryDependencyBundle) (*VerifiedRecoveryDAG, error) {
	if _, e := recordRows(bundle.Records); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(bundle)
	if e != nil || ValidateStrictJSON(raw, MaxRecoveryAuthorityBytes) != nil {
		return nil, ErrInvalidWire
	}
	// 私有受信对象不共享调用者可修改的 slice/指针。
	var copied RecoveryDependencyBundle
	if e = strictDAGDecode(raw, &copied); e != nil {
		return nil, e
	}
	bundle = copied
	initial, e := VerifyRecoveryInitialization(pin, bundle.Initialization)
	if e != nil {
		return nil, e
	}
	ih, e := bundle.Initialization.Hash()
	if e != nil {
		return nil, e
	}
	d := &VerifiedRecoveryDAG{pin: pin, original: bundle.Initialization, initializationHash: ih, current: initial, heads: map[string]*VerifiedRecoveryAuthority{ih: initial}, records: map[string]RecoveryDAGRecord{}, sequences: map[string]uint64{}, dependencies: map[string][]RecoveryDependency{}, recovered: map[string]*VerifiedRecoveredDevice{}, recoveredGrants: map[string][]SignedGrantWire{}, publicOwners: map[string]string{}, identities: map[string]issuerIdentity{}, sourceMemo: map[string]*VerifiedIssuerProofV2{}, lastSequence: 1}
	if e = d.addIdentity(issuerIdentity{pin.DeviceID, pin.SigningPublicKey, pin.ReceivingPublicKey}); e != nil {
		return nil, e
	}
	if e = d.addRecoveryKeys(initial); e != nil {
		return nil, e
	}
	rows := append([]RecoveryDAGRecord(nil), bundle.Records...)
	sort.Slice(rows, func(i, j int) bool {
		a, _ := rows[i].row()
		b, _ := rows[j].row()
		x, _ := strconv.ParseUint(a[5], 10, 64)
		y, _ := strconv.ParseUint(b[5], 10, 64)
		return x < y
	})
	operations := map[string]bool{}
	for _, r := range rows {
		row, e := r.row()
		if e != nil {
			return nil, e
		}
		seq, _ := strconv.ParseUint(row[5], 10, 64)
		if seq <= d.lastSequence {
			return nil, ErrInvalidWire
		}
		deps, e := d.recordDependencies(r, seq-1)
		if e != nil {
			return nil, e
		}
		d.edges += len(deps)
		if d.edges > MaxRecoveryDAGEdges {
			return nil, ErrInvalidWire
		}
		var recovered *VerifiedRecoveredDevice
		var next *VerifiedRecoveryAuthority
		var graph *VerifiedIssuerProofV2
		var op string
		var grants []SignedGrantWire
		switch r.Kind {
		case "transition-v2":
			s := r.TransitionV2.Submission
			op = s.Transition.OperationID
			if s.IssuerEvidence != nil {
				graph, e = d.sourceGraph(*s.IssuerEvidence, seq-1)
				if e != nil {
					return nil, e
				}
			}
			next, e = verifyAcceptedTransitionV2(d, *r.TransitionV2)
		case "recovered-v2":
			s := r.RecoveredV2.Submission
			op = s.Enrollment.OperationID
			graph, e = d.validateRecoveredV2(s, nil)
			if e == nil {
				recovered, e = verifyAcceptedRecoveredV2(d, *r.RecoveredV2)
			}
			grants = s.Grants
		}
		if e != nil {
			return nil, e
		}
		if operations[op] {
			return nil, ErrInvalidWire
		}
		operations[op] = true
		if e = d.mergeGraph(graph); e != nil {
			return nil, e
		}
		if next != nil {
			if e = d.addRecoveryKeys(next); e != nil {
				return nil, e
			}
			d.current = next
			d.heads[next.head] = next
		}
		if recovered != nil {
			if e = d.addIdentity(issuerIdentity{recovered.deviceID, recovered.signingPublic, recovered.receivingPublic}); e != nil {
				return nil, e
			}
			d.recovered[row[1]] = recovered
			d.recoveredGrants[row[1]] = grants
		}
		d.records[row[1]] = r
		d.sequences[row[1]] = seq
		d.dependencies[row[1]] = deps
		d.lastSequence = seq
	}
	return d, nil
}
func (d *VerifiedRecoveryDAG) checkClosure(source RecoverySource) error {
	deps, e := d.sourceDependencies(source, d.lastSequence)
	if e != nil {
		return e
	}
	needed := map[string]bool{}
	if d.current.head != d.initializationHash {
		needed[d.current.head] = true
	}
	queue := make([]string, 0, len(deps)+1)
	for _, dep := range deps {
		needed[dep.ReferenceHash] = true
	}
	for h := range needed {
		queue = append(queue, h)
	}
	for i := 0; i < len(queue); i++ {
		if i >= MaxRecoveryDAGNodes {
			return ErrInvalidWire
		}
		for _, dep := range d.dependencies[queue[i]] {
			if !needed[dep.ReferenceHash] {
				needed[dep.ReferenceHash] = true
				queue = append(queue, dep.ReferenceHash)
			}
		}
	}
	if len(needed) != len(d.records) {
		return ErrInvalidWire
	}
	return nil
}
func VerifyIssuerRecoveryDAG(pin PinnedIssuerRoot, p IssuerRecoveryDAG) (*VerifiedRecoveryDAG, error) {
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxRecoveryAuthorityBytes {
		return nil, ErrInvalidWire
	}
	isolated, e := DecodeIssuerRecoveryDAG(raw)
	if e != nil {
		return nil, e
	}
	p = isolated
	if _, e := p.CanonicalBytes(); e != nil {
		return nil, e
	}
	d, e := VerifyRecoveryDependencyBundle(pin, RecoveryDependencyBundle{p.Initialization, p.Records})
	if e != nil {
		return nil, e
	}
	if e = d.checkClosure(p.Source); e != nil {
		return nil, e
	}
	g, e := d.sourceGraph(p.Source, 9007199254740991)
	if e != nil {
		return nil, e
	}
	root, e := sourceRoot(p.Source)
	if e != nil || root.RecoveryGeneration != d.current.recoveryGeneration || root.RecoverySigningPublicKey != d.current.signingPublic || root.RecoveryReceivingPublicKey != d.current.receivingPublic {
		return nil, ErrInvalidSignature
	}
	if e = d.mergeGraph(g); e != nil {
		return nil, e
	}
	d.graph = g
	return d, nil
}

func (d *VerifiedRecoveryDAG) RecoveryCheckpoint() (IssuerRecoveryCheckpoint, error) {
	if d == nil {
		return IssuerRecoveryCheckpoint{}, ErrInvalidWire
	}
	return IssuerRecoveryCheckpoint{AccountID: d.pin.AccountID, AccountGeneration: d.pin.AccountGeneration, RecoveryGeneration: d.current.recoveryGeneration, SigningPublicKey: d.current.signingPublic, ReceivingPublicKey: d.current.receivingPublic, TransitionHead: d.current.head, AcceptedSequence: d.current.sequence}, nil
}
func (d *VerifiedRecoveryDAG) VerifyHistoricalGrant(s SignedGrantWire) error {
	if d == nil || d.graph == nil {
		return ErrInvalidWire
	}
	return d.graph.VerifyHistoricalGrant(s)
}
func (d *VerifiedRecoveryDAG) VerifyTarget(s SignedGrantWire, id, ed, x string) error {
	if d == nil || d.graph == nil {
		return ErrInvalidWire
	}
	return d.graph.VerifyTarget(s, id, ed, x)
}
func (d *VerifiedRecoveryDAG) Authority(h string) (SignedGrantWire, bool) {
	if d == nil || d.graph == nil {
		return SignedGrantWire{}, false
	}
	return d.graph.Authority(h)
}
func (d *VerifiedRecoveryDAG) VerifiedIdentity(id string) (VerifiedIssuerIdentity, bool) {
	if d == nil || d.graph == nil {
		return VerifiedIssuerIdentity{}, false
	}
	v, ok := d.graph.identities[id]
	return VerifiedIssuerIdentity{v.id, v.signing, v.receiving}, ok
}
func (d *VerifiedRecoveryDAG) IssuerBindings() []IssuerBinding {
	if d == nil || d.graph == nil {
		return nil
	}
	return d.graph.IssuerBindings()
}
func (d *VerifiedRecoveryDAG) InitialAuthorities() []SignedGrantWire {
	if d == nil {
		return nil
	}
	return d.current.InitialAuthorities()
}
func (d *VerifiedRecoveryDAG) VerifyEnvironmentOriginEvent(c SignedEnvironmentChange, o SignedEnvironmentOrigin, g SignedGrantWire) error {
	if d == nil || d.graph == nil {
		return ErrInvalidWire
	}
	return d.graph.VerifyEnvironmentOriginEvent(c, o, g)
}
func (d *VerifiedRecoveryDAG) VerifyHistoricalMutationSource(m SignedMutationWire, g SignedGrantWire) error {
	if d == nil || d.graph == nil {
		return ErrInvalidWire
	}
	v := VerifiedIssuerRecoveryProof{graph: d.graph, recovery: d.current}
	return v.VerifyHistoricalMutationSource(m, g)
}
func VerifyRecoveryDAGAdvance(prior *VerifiedRecoveryDAG, p IssuerRecoveryDAG) (*VerifiedRecoveryDAG, error) {
	if prior == nil {
		return nil, ErrInvalidWire
	}
	next, e := VerifyIssuerRecoveryDAG(prior.pin, p)
	if e != nil {
		return nil, e
	}
	old := prior.current
	head, ok := next.heads[old.head]
	if !ok || head.sequence != old.sequence || head.signingPublic != old.signingPublic || head.receivingPublic != old.receivingPublic || head.recoveryGeneration != old.recoveryGeneration || next.current.sequence < old.sequence || next.initializationHash != prior.initializationHash {
		return nil, ErrInvalidSignature
	}
	for pub, owner := range prior.publicOwners {
		if current := next.publicOwners[pub]; current != "" && current != owner {
			return nil, ErrInvalidSignature
		}
		next.publicOwners[pub] = owner
	}
	for id, identity := range prior.identities {
		if current, ok := next.identities[id]; ok && current != identity {
			return nil, ErrInvalidSignature
		}
		next.identities[id] = identity
	}
	return next, nil
}
