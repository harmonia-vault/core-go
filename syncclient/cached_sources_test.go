package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// 从已验源图产生真实签名 before/after、完整轮换清单与 HPKE 封套。
func cacheRotation(t *testing.T, f originClientFixture, p cryptox.IssuerRecoveryDAG, keyVersion string, sequence uint64) (cryptox.IssuerRecoveryDAG, Pull) {
	t.Helper()
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	before := []cryptox.SignedGrantWire{}
	var authority cryptox.SignedGrantWire
	for _, n := range p.Source.View.Authorities {
		g := n.Grant.Grant
		if g.EnvironmentID == "env-fixture" && g.KeyVersion == keyVersion {
			before = append(before, n.Grant)
			if g.SubjectDeviceID == "device-B" {
				authority = n.Grant
			}
		}
	}
	next := strconv.FormatUint(environmentUint(t, keyVersion)+1, 10)
	after := []cryptox.SignedGrantWire{}
	var own SignedGrant
	for _, s := range before {
		g := s.Grant
		g.IssuerDeviceID = "device-B"
		g.KeyVersion = next
		g.GrantGeneration = strconv.FormatUint(environmentUint(t, g.GrantGeneration)+1, 10)
		g.IdempotencyKey = "cache-rotate-" + next + "-" + g.SubjectDeviceID
		packet, e := cryptox.WrapEnvironmentKey(bytes.Repeat([]byte{byte(sequence)}, 32), cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: next, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey})
		check(t, e)
		g.Envelope = cryptox.EncodeBase64(packet)
		signed, e := cryptox.SignGrant(g, manager)
		check(t, e)
		after = append(after, cryptox.GrantToWire(signed))
		if g.SubjectDeviceID == "device-D" {
			own = SignedGrant{Grant: g, Signature: signed.Signature}
		}
	}
	change := f.Rotation.Change
	change.AuthorityKeyVersion = keyVersion
	change.AuthorityGrantGeneration = authority.Grant.GrantGeneration
	change.PreviousKeyVersion = keyVersion
	change.KeyVersion = next
	change.ExpectedSequence = strconv.FormatUint(sequence-1, 10)
	change.IdempotencyKey = "cache-rotate-" + next
	change.Grants = after
	change.Mutations = []cryptox.SignedMutationWire{}
	signed, e := cryptox.SignEnvironmentChange(change, manager)
	check(t, e)
	reference, e := cryptox.EnvironmentChangeReferenceHash(signed)
	check(t, e)
	authorityHash, e := cryptox.IssuerAuthorityHash(authority)
	check(t, e)
	beforeRows, e := cryptox.EnvironmentRights(before)
	check(t, e)
	afterRows, e := cryptox.EnvironmentRights(after)
	check(t, e)
	o, e := cryptox.SignEnvironmentOrigin(cryptox.EnvironmentOrigin{AccountID: change.AccountID, AccountGeneration: change.AccountGeneration, ActorDeviceID: "device-B", EnvironmentID: change.EnvironmentID, Operation: "rotate", AuthorityEnvironmentID: change.EnvironmentID, AuthorityKeyVersion: keyVersion, AuthorityGrantGeneration: authority.Grant.GrantGeneration, PreviousKeyVersion: keyVersion, KeyVersion: next, ExpectedSequence: change.ExpectedSequence, IdempotencyKey: change.IdempotencyKey, ChangeHash: reference, AuthorityHash: authorityHash, Before: beforeRows, After: afterRows}, manager)
	check(t, e)
	oh, e := cryptox.EnvironmentOriginHash(o)
	check(t, e)
	p = cloneDAGEvidence(p)
	p.Source.View.Origins = append(p.Source.View.Origins, o)
	for _, s := range after {
		var previous string
		for _, b := range before {
			if b.Grant.SubjectDeviceID == s.Grant.SubjectDeviceID {
				previous, e = cryptox.IssuerAuthorityHash(b)
				check(t, e)
			}
		}
		p.Source.View.Authorities = append(p.Source.View.Authorities, cryptox.IssuerRecoveryAuthority{Grant: s, ParentHash: authorityHash, OriginHash: oh, PreviousGrantHash: previous})
	}
	target, e := cryptox.IssuerAuthorityHash(cryptox.SignedGrantWire{Grant: own.Grant, Signature: own.Signature})
	check(t, e)
	p.Source.View.Targets = []cryptox.IssuerTarget{{EnvironmentID: "env-fixture", AuthorityHash: target}}
	normalizeDAG(&p)
	return p, Pull{AccountID: change.AccountID, AccountGeneration: change.AccountGeneration, Sequence: sequence, Scope: "authorizations", Grants: []SignedGrant{own}, IssuerDAGEvidence: &p}
}
func environmentUint(t *testing.T, s string) uint64 {
	t.Helper()
	n, e := strconv.ParseUint(s, 10, 64)
	check(t, e)
	return n
}
func clonedCloud(t *testing.T, s localstate.CloudSnapshot) localstate.CloudSnapshot {
	t.Helper()
	b, e := json.Marshal(s)
	check(t, e)
	var out localstate.CloudSnapshot
	check(t, json.Unmarshal(b, &out))
	return out
}

func TestPausedCacheRotationContinuousOriginsAndRestart(t *testing.T) {
	f, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	store := &failedOriginStore{volatileStore: volatileStore{state: localstate.EmptyState()}}
	engine, e := localstate.New(store)
	check(t, e)
	first, e := v.VerifyPull(context.Background(), pull, engine.State().Cloud)
	check(t, e)
	check(t, engine.AcceptDataSnapshotAtEpoch(first, trust.Now(), engine.State().SessionEpoch))
	check(t, engine.SetPaused(true))
	p, auth := cacheRotation(t, f, *pull.IssuerDAGEvidence, "2", 21)
	projected, e := v.VerifyAuthorizationRefresh(context.Background(), auth, first)
	check(t, e)
	old := first.Environments["env-fixture"]
	next := projected.Environments[old.ID]
	if next.KeyVersion != old.KeyVersion || next.GrantGeneration != old.GrantGeneration || !sameJSON(old.Values, next.Values) || next.Source.AuthorityHash != old.Source.AuthorityHash || next.Source.Fingerprint != old.Source.Fingerprint || len(next.Source.AuthorizationPath) != 2 || projected.GrantCheckpoints[old.ID] != 2 || projected.Sequence != first.Sequence || projected.AuthorizationSequence != 21 || !sameJSON(first.SeenMutations, projected.SeenMutations) {
		t.Fatal("rotation changed cached data source or failed current authorization")
	}
	store.fail = true
	if engine.AcceptAuthorizationRefreshAtEpoch(projected, trust.Now(), engine.State().SessionEpoch) == nil || !sameJSON(engine.State().Cloud, first) {
		t.Fatal("failed encrypted commit partly installed source path")
	}
	store.fail = false
	check(t, engine.AcceptAuthorizationRefreshAtEpoch(projected, trust.Now(), engine.State().SessionEpoch))
	reopened, e := localstate.New(store)
	check(t, e)
	check(t, v.ValidateStoredIssuerEvidence(reopened.State().Cloud))
	_, auth2 := cacheRotation(t, f, p, "3", 22)
	twice, e := v.VerifyAuthorizationRefresh(context.Background(), auth2, reopened.State().Cloud)
	check(t, e)
	check(t, engine.AcceptAuthorizationRefreshAtEpoch(twice, trust.Now(), engine.State().SessionEpoch))
	check(t, v.ValidateStoredIssuerEvidence(engine.State().Cloud))
	if len(twice.Environments[old.ID].Source.AuthorizationPath) != 3 || twice.GrantCheckpoints[old.ID] != 3 || twice.Environments[old.ID].KeyVersion != 2 {
		t.Fatal("second rotation lost source chain")
	}
	// 两次轮换都漏收时，完整真实来源仍能从旧源连续重建，而不是放宽旧KV。
	caught, e := v.VerifyAuthorizationRefresh(context.Background(), auth2, first)
	check(t, e)
	if !sameJSON(caught, twice) {
		t.Fatal("missed consecutive origins did not catch up deterministically")
	}
	for _, kind := range []string{"source-fingerprint", "source-hash", "short-path", "skip-generation", "wrong-current-target", "current-fingerprint", "source-KV", "source-GG", "cycle", "missing-origin", "mutated-before"} {
		t.Run(kind, func(t *testing.T) {
			bad := clonedCloud(t, twice)
			env := bad.Environments[old.ID]
			switch kind {
			case "source-fingerprint":
				env.Source.Fingerprint = strings.Repeat("0", 64)
			case "source-hash":
				env.Source.AuthorityHash = env.Source.AuthorizationPath[1]
			case "short-path":
				env.Source.AuthorizationPath = env.Source.AuthorizationPath[:2]
			case "skip-generation":
				env.Source.AuthorizationPath = []string{env.Source.AuthorityHash, env.Source.AuthorizationPath[2]}
			case "wrong-current-target":
				var ledger cryptox.IssuerRecoveryDAG
				check(t, json.Unmarshal(bad.IssuerEvidence, &ledger))
				ledger.Source.View.Targets[0].AuthorityHash = env.Source.AuthorityHash
				bad.IssuerEvidence, _ = json.Marshal(ledger)
			case "current-fingerprint":
				bad.GrantFingerprints[old.ID] = strings.Repeat("f", 64)
			case "source-KV":
				env.KeyVersion++
			case "source-GG":
				env.GrantGeneration++
			case "cycle":
				env.Source.AuthorizationPath = append(env.Source.AuthorizationPath, env.Source.AuthorityHash)
			case "missing-origin":
				var ledger cryptox.IssuerRecoveryDAG
				check(t, json.Unmarshal(bad.IssuerEvidence, &ledger))
				ledger.Source.View.Origins = ledger.Source.View.Origins[:len(ledger.Source.View.Origins)-1]
				bad.IssuerEvidence, _ = json.Marshal(ledger)
			case "mutated-before":
				var ledger cryptox.IssuerRecoveryDAG
				check(t, json.Unmarshal(bad.IssuerEvidence, &ledger))
				for i := range ledger.Source.View.Origins {
					if len(ledger.Source.View.Origins[i].Origin.Before) > 0 {
						ledger.Source.View.Origins[i].Origin.Before[0].SubjectReceivingPublicKey = cryptox.EncodeBase64(bytes.Repeat([]byte{77}, 32))
						break
					}
				}
				bad.IssuerEvidence, _ = json.Marshal(ledger)
			}
			bad.Environments[old.ID] = env
			if v.ValidateStoredIssuerEvidence(bad) == nil {
				t.Fatal("corrupt source/current/origin trusted on restart")
			}
		})
	}
	// 修改路径前缀不能抹去已收到的限制，即使外部验证器错误地交给Engine。
	bad := clonedCloud(t, twice)
	env := bad.Environments[old.ID]
	env.Source.AuthorizationPath = []string{env.Source.AuthorityHash, env.Source.AuthorizationPath[2]}
	bad.Environments[old.ID] = env
	bad.AuthorizationSequence++
	if engine.AcceptAuthorizationRefreshAtEpoch(bad, trust.Now(), engine.State().SessionEpoch) == nil {
		t.Fatal("engine replaced observed authorization prefix")
	}
	missing := clonedCloud(t, first)
	env = missing.Environments[old.ID]
	env.Source = nil
	missing.Environments[old.ID] = env
	if _, e = v.VerifyAuthorizationRefresh(context.Background(), auth, missing); e == nil {
		t.Fatal("cached source was reconstructed from an obsolete state")
	}
}

func TestPausedCachedSourceMissingOwnScopeCleansWithoutDataAdvance(t *testing.T) {
	_, trust, pull := originClientVector(t)
	v, e := NewPinnedVerifierV5(trust)
	check(t, e)
	defer v.Close()
	engine := testEngine(t)
	first, e := v.VerifyPull(context.Background(), pull, engine.State().Cloud)
	check(t, e)
	check(t, engine.AcceptDataSnapshotAtEpoch(first, trust.Now(), engine.State().SessionEpoch))
	check(t, engine.Activate("env-fixture", 1, trust.Now()))
	check(t, engine.SetOverride("env-fixture", "FIXTURE_VALUE", "synthetic-offline-override", trust.Now()))
	check(t, engine.SetPaused(true))
	missing := clonePullOrigin(t, pull)
	missing.Scope = "authorizations"
	missing.Sequence++
	missing.Grants = nil
	missing.Events = nil
	missing.EnvironmentEvents = nil
	missing.IssuerDAGEvidence.Source.View.Targets = []cryptox.IssuerTarget{}
	projected, e := v.VerifyAuthorizationRefresh(context.Background(), missing, first)
	check(t, e)
	check(t, engine.AcceptAuthorizationRefreshAtEpoch(projected, trust.Now(), engine.State().SessionEpoch))
	current := engine.State()
	if len(current.Cloud.Environments) != 0 || len(current.Overrides) != 0 || !current.SafetyKeys["FIXTURE_VALUE"] || current.Cloud.Sequence != first.Sequence || !sameJSON(current.Cloud.SeenMutations, first.SeenMutations) {
		t.Fatal("missing exact own scope retained paused data/override or advanced data checkpoint")
	}
	check(t, v.ValidateStoredIssuerEvidence(current.Cloud))
}
