package cryptox

// verifyRecoverySourceGraph 复用原 Proof3 的身份、授权及完整 origin 核验。
// 调用方必须已经独立验证原初始化与所有恢复记录；本 helper 不建立根 pin。
func verifyRecoverySourceGraph(pin PinnedIssuerRoot, authority *VerifiedRecoveryAuthority, p IssuerRecoveryProof, recovered map[string]*VerifiedRecoveredDevice, recoveredGrants [][]SignedGrantWire, archiveBytes func(IssuerEnrollment) ([]byte, error)) (*VerifiedIssuerRecoveryProof, error) {
	var e error
	v := &VerifiedIssuerProofV2{p.AccountID, p.AccountGeneration, map[string]issuerIdentity{}, map[string]IssuerAuthorityV2{}, map[string]SignedEnvironmentOrigin{}, map[string]string{}, nil}
	used := map[string]string{}
	for pub := range authority.usedRecoveryKeys {
		used[pub] = "recovery"
	}
	add := func(id issuerIdentity) error {
		if validatePublicPair(id.signing, id.receiving) != nil {
			return ErrInvalidWire
		}
		if old, ok := v.identities[id.id]; ok {
			if old != id {
				return ErrInvalidWire
			}
			return nil
		}
		for _, pub := range []string{id.signing, id.receiving} {
			if _, ok := used[pub]; ok {
				return ErrInvalidWire
			}
		}
		v.identities[id.id] = id
		used[id.signing] = id.id
		used[id.receiving] = id.id
		return nil
	}
	identityRoot := issuerIdentity{pin.DeviceID, pin.SigningPublicKey, pin.ReceivingPublicKey}
	if e = add(identityRoot); e != nil {
		return nil, e
	}
	archived := map[string]string{}
	taggedPaths := append([][]IssuerRecoveryArchive{p.Path}, p.IdentityPaths...)
	allPaths := [][]IssuerEnrollment{}
	for _, path := range taggedPaths {
		current := identityRoot
		pathIDs := map[string]bool{current.id: true}
		paired := []IssuerEnrollment{}
		for i, node := range path {
			if node.Kind == "recovered" {
				if i != 0 {
					return nil, ErrInvalidWire
				}
				d, ok := recovered[node.RecoveryEnrollmentHash]
				if !ok {
					return nil, ErrInvalidSignature
				}
				child := issuerIdentity{d.deviceID, d.signingPublic, d.receivingPublic}
				if pathIDs[child.id] {
					return nil, ErrInvalidWire
				}
				if old, ok := archived[child.id]; ok && old != node.RecoveryEnrollmentHash {
					return nil, ErrInvalidWire
				}
				archived[child.id] = node.RecoveryEnrollmentHash
				if e = add(child); e != nil {
					return nil, e
				}
				pathIDs[child.id] = true
				current = child
				continue
			}
			n := *node.Enrollment
			c := n.Approval.Context
			if c.AccountID != p.AccountID || c.AccountGeneration != p.AccountGeneration || issuerHistoricalContext(c) != nil || !issuerIdentityMatches(current, c.ApproverDeviceID, c.ApproverSigningPublicKey, c.ApproverReceivingPublicKey) || pathIDs[c.InitiatorDeviceID] {
				return nil, ErrInvalidWire
			}
			b, e := archiveBytes(n)
			if e != nil {
				return nil, e
			}
			nodeHash, e := hashCanonical([]string{EncodeBase64(b), n.Approval.ApproverSignature, n.Approval.InitiatorSignature})
			if e != nil {
				return nil, e
			}
			if old, ok := archived[c.InitiatorDeviceID]; ok && old != nodeHash {
				return nil, ErrInvalidWire
			}
			archived[c.InitiatorDeviceID] = nodeHash
			parentKey, _ := DecodeBase64(current.signing, 32, 32)
			if e = verify(parentKey, b, n.Approval.ApproverSignature); e != nil {
				return nil, e
			}
			child := issuerIdentity{c.InitiatorDeviceID, c.InitiatorSigningPublicKey, c.InitiatorReceivingPublicKey}
			if e = add(child); e != nil {
				return nil, e
			}
			childKey, _ := DecodeBase64(child.signing, 32, 32)
			if e = verify(childKey, b, n.Approval.InitiatorSignature); e != nil {
				return nil, e
			}
			base, e := n.Approval.Certificate()
			if e != nil {
				return nil, e
			}
			if e = VerifyEnrollmentGrants(base, n.Approval.Grants, parentKey); e != nil {
				return nil, e
			}
			pathIDs[child.id] = true
			current = child
			paired = append(paired, n)
		}
		allPaths = append(allPaths, paired)
	}
	genesis := map[string]SignedGrantWire{}
	for _, s := range authority.initial {
		h, e := IssuerAuthorityHash(s)
		if e != nil {
			return nil, e
		}
		genesis[h] = s
	}
	rights := map[string]IssuerRecoveryAuthority{}
	seenGen, seenOp := map[string]string{}, map[string]string{}
	checkUnique := func(s SignedGrantWire) error {
		g := s.Grant
		h, e := IssuerAuthorityHash(s)
		if e != nil {
			return e
		}
		if g.AccountID != p.AccountID || g.AccountGeneration != p.AccountGeneration {
			return ErrInvalidWire
		}
		for id, table := range map[string]map[string]string{"gen/" + g.EnvironmentID + "/" + g.SubjectDeviceID + "/" + g.GrantGeneration: seenGen, "op/" + g.IssuerDeviceID + "/" + g.IdempotencyKey: seenOp} {
			if old, ok := table[id]; ok && old != h {
				return ErrInvalidWire
			}
			table[id] = h
		}
		return nil
	}
	for _, grants := range recoveredGrants {
		for _, g := range grants {
			if e = checkUnique(g); e != nil {
				return nil, e
			}
		}
	}
	for _, path := range allPaths {
		for _, n := range path {
			for _, g := range n.Approval.Grants {
				if e = checkUnique(g); e != nil {
					return nil, e
				}
			}
		}
	}
	for _, a := range p.Authorities {
		g := a.Grant.Grant
		if e = checkUnique(a.Grant); e != nil {
			return nil, e
		}
		sub, ok := v.identities[g.SubjectDeviceID]
		issuer, iok := v.identities[g.IssuerDeviceID]
		if !ok || !iok || !issuerIdentityMatches(sub, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) || !issuerExpiryWithin(g.ExpiresAt, "0") {
			return nil, ErrInvalidWire
		}
		key, _ := DecodeBase64(issuer.signing, 32, 32)
		if e = VerifyGrant(a.Grant.SignedGrant(), key); e != nil {
			return nil, e
		}
		h, _ := IssuerAuthorityHash(a.Grant)
		if _, ok = v.authorities[h]; ok {
			return nil, ErrInvalidWire
		}
		v.authorities[h] = IssuerAuthorityV2{a.Grant, a.ParentHash, a.OriginHash, a.PreviousGrantHash}
		rights[h] = a
	}
	for _, s := range p.Origins {
		o := s.Origin
		if o.AccountID != p.AccountID || o.AccountGeneration != p.AccountGeneration {
			return nil, ErrInvalidWire
		}
		actor, ok := v.identities[o.ActorDeviceID]
		if !ok {
			return nil, ErrInvalidSignature
		}
		key, _ := DecodeBase64(actor.signing, 32, 32)
		if e = VerifyEnvironmentOrigin(s, key); e != nil {
			return nil, e
		}
		h, _ := EnvironmentOriginHash(s)
		v.origins[h] = s
	}
	states := map[string]uint8{}
	originStates := map[string]uint8{}
	var checkRight func(string) error
	var checkOrigin func(string) error
	match := func(r EnvironmentRight, g SignedGrantWire, o EnvironmentOrigin, version string) bool {
		rs, e := EnvironmentRights([]SignedGrantWire{g})
		return e == nil && rs[0] == r && g.Grant.AccountID == o.AccountID && g.Grant.AccountGeneration == o.AccountGeneration && g.Grant.EnvironmentID == o.EnvironmentID && g.Grant.KeyVersion == version
	}
	checkOrigin = func(h string) error {
		if originStates[h] == 2 {
			return nil
		}
		if originStates[h] == 1 {
			return ErrInvalidWire
		}
		s, ok := v.origins[h]
		if !ok {
			return ErrInvalidWire
		}
		originStates[h] = 1
		o := s.Origin
		if e := checkRight(o.AuthorityHash); e != nil {
			return e
		}
		actor := v.authorities[o.AuthorityHash].Grant.Grant
		if actor.Role != "admin" || actor.SubjectDeviceID != o.ActorDeviceID || actor.EnvironmentID != o.AuthorityEnvironmentID || actor.KeyVersion != o.AuthorityKeyVersion || actor.GrantGeneration != o.AuthorityGrantGeneration {
			return ErrInvalidWire
		}
		for _, r := range o.Before {
			if e := checkRight(r.GrantHash); e != nil {
				return e
			}
			a, ok := v.authorities[r.GrantHash]
			if !ok || !match(r, a.Grant, o, o.PreviousKeyVersion) {
				return ErrInvalidWire
			}
		}
		for i, r := range o.After {
			a, ok := v.authorities[r.GrantHash]
			if !ok || !match(r, a.Grant, o, o.KeyVersion) || a.Grant.Grant.IssuerDeviceID != o.ActorDeviceID || a.ParentHash != o.AuthorityHash || a.OriginHash != h {
				return ErrInvalidWire
			}
			if o.Operation == "create" {
				if a.PreviousGrantHash != "" || !issuerExpiryWithin(r.ExpiresAt, actor.ExpiresAt) || r.SubjectSigningPublicKey != actor.SubjectSigningPublicKey || r.SubjectReceivingPublicKey != actor.SubjectReceivingPublicKey {
					return ErrInvalidWire
				}
			} else if a.PreviousGrantHash != o.Before[i].GrantHash {
				return ErrInvalidWire
			}
		}
		originStates[h] = 2
		return nil
	}
	checkRight = func(h string) error {
		if states[h] == 2 {
			return nil
		}
		if states[h] == 1 {
			return ErrInvalidWire
		}
		a, ok := v.authorities[h]
		if !ok {
			return ErrInvalidWire
		}
		states[h] = 1
		g := a.Grant.Grant
		switch {
		case rights[h].RecoveryEnrollmentHash != "":
			r, ok := recovered[rights[h].RecoveryEnrollmentHash]
			if !ok || a.ParentHash != "" || a.OriginHash != "" || a.PreviousGrantHash != "" || r.VerifySourceGrant(a.Grant) != nil {
				return ErrInvalidSignature
			}
		case a.OriginHash != "":
			if a.ParentHash == "" {
				return ErrInvalidWire
			}
			if e := checkOrigin(a.OriginHash); e != nil {
				return e
			}
			o := v.origins[a.OriginHash].Origin
			found := false
			for _, r := range o.After {
				if r.GrantHash == h {
					found = true
				}
			}
			if !found {
				return ErrInvalidWire
			}
		case a.ParentHash == "":
			if _, anchored := genesis[h]; !anchored {
				return ErrInvalidSignature
			}
			v.genesis = append(v.genesis, a.Grant)
			if a.PreviousGrantHash != "" || g.Role != "admin" || g.KeyVersion != "1" || g.GrantGeneration != "1" || g.ExpiresAt != "0" || g.IssuerDeviceID != identityRoot.id || !issuerIdentityMatches(identityRoot, g.SubjectDeviceID, g.SubjectSigningPublicKey, g.SubjectReceivingPublicKey) {
				return ErrInvalidWire
			}
		default:
			if a.PreviousGrantHash != "" {
				return ErrInvalidWire
			}
			if e := checkRight(a.ParentHash); e != nil {
				return e
			}
			if e := v.VerifyDelegatedGrant(a.Grant, a.ParentHash); e != nil {
				return e
			}
		}
		states[h] = 2
		return nil
	}
	for h := range v.authorities {
		if e = checkRight(h); e != nil {
			return nil, e
		}
	}
	for h := range v.origins {
		if e = checkOrigin(h); e != nil {
			return nil, e
		}
	}
	for _, path := range allPaths {
		for _, n := range path {
			for _, g := range n.Approval.Grants {
				if e = v.VerifyHistoricalGrant(g); e != nil {
					return nil, e
				}
			}
		}
	}
	for _, t := range p.Targets {
		a, ok := v.authorities[t.AuthorityHash]
		if !ok || a.Grant.Grant.EnvironmentID != t.EnvironmentID {
			return nil, ErrInvalidWire
		}
		v.targets[t.EnvironmentID] = t.AuthorityHash
	}
	return &VerifiedIssuerRecoveryProof{graph: v, recovery: authority}, nil
}
