package syncclient

import (
	"bytes"
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/internal/dagrecoveredfixture"
	"sort"
	"strconv"
	"testing"
)

func b3Preparation(t *testing.T, f dagrecoveredfixture.Fixture, endpoint string) (DAGRecoveredPreparation, ProtectedDAGOperation, ProtectedDAGOperation) {
	t.Helper()
	sub := f.Submission
	e := sub.Enrollment
	gen, _ := strconv.ParseUint(f.Pin.AccountGeneration, 10, 64)
	seq, _ := strconv.ParseUint(e.ExpectedSequence, 10, 64)
	expiry, _ := strconv.ParseInt(e.ExpiresAt, 10, 64)
	hash, err := cryptox.RecoveredDeviceReferenceHashV2(sub)
	if err != nil {
		t.Fatal(err)
	}
	priorHash, err := cryptox.RecoveryTransitionHashV2(f.Prior.Submission)
	if err != nil {
		t.Fatal(err)
	}
	initHash, err := f.Bundle.Initialization.Hash()
	if err != nil {
		t.Fatal(err)
	}
	prior := ProtectedDAGOperation{Version: 1, Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "transition-v2", OperationID: f.Prior.Submission.Transition.OperationID, ContentHash: priorHash, Transition: &cryptox.RecoveryTransitionCommandV2{Submission: f.Prior.Submission, DependencyBundle: cryptox.RecoveryDependencyBundle{Initialization: f.Bundle.Initialization, Records: f.Bundle.Records[:2]}}, Attempted: true, AcceptedSequence: f.Prior.Sequence, Applied: true}
	next := ProtectedDAGOperation{Version: 1, Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, Kind: "recovered-v2", OperationID: e.OperationID, ContentHash: hash, Recovered: &cryptox.RecoveredDeviceCommandV2{Submission: sub, DependencyBundle: f.Bundle}}
	p := DAGRecoveredPreparation{Version: 1, Kind: "recovered-v2", Phase: "challenged", Endpoint: endpoint, AccountID: f.Pin.AccountID, AccountGeneration: gen, Pin: f.Pin, InitializationHash: initHash, InitializationProposalHash: f.Bundle.Initialization.Proof.ProposalHash, RestrictedSessionHash: e.RestrictedSessionHash, OperationID: e.OperationID, ExpectedSequence: seq, RecoveryGeneration: e.RecoveryGeneration, RecoveryHeadHash: e.RecoveryTransitionHash, RecoverySigningPublicKey: f.Prior.Submission.Transition.NewRecoverySigningPublicKey, RecoveryReceivingPublicKey: f.Prior.Submission.Transition.NewRecoveryReceivingPublicKey, DeviceID: e.DeviceID, DeviceSigningPublicKey: e.DeviceSigningPublicKey, DeviceReceivingPublicKey: e.DeviceReceivingPublicKey, BaseBundle: f.Bundle, EnvironmentManifest: f.Prior.Submission.EnvironmentManifest, SelectedRights: sub.SelectedRights, SelectedRightsHash: e.SelectedRightsHash, PriorOperationID: prior.OperationID, PriorContentHash: prior.ContentHash, PriorAcceptedSequence: prior.AcceptedSequence, Challenge: &DAGDeviceChallenge{OperationID: e.OperationID, ChallengeID: e.ChallengeID, Nonce: e.Nonce, ExpiresAt: expiry, AccountGeneration: e.AccountGeneration, RestrictedSessionHash: e.RestrictedSessionHash, ExpectedSequence: e.ExpectedSequence, RecoveryGeneration: e.RecoveryGeneration, RecoveryTransitionHash: e.RecoveryTransitionHash, DeviceID: e.DeviceID, DeviceSigningPublicKey: e.DeviceSigningPublicKey, DeviceReceivingPublicKey: e.DeviceReceivingPublicKey, DependencyBundle: f.Bundle, IssuerEvidence: sub.IssuerEvidence}}
	raw, _ := json.Marshal(p)
	if _, err = DecodeDAGRecoveredPreparation(raw); err != nil {
		t.Fatal("valid signed preparation prerequisite", err)
	}
	return p, prior, next
}
func b3Intent(p DAGRecoveredPreparation) DAGRecoveredPreparation {
	p.Phase = "intent"
	p.Challenge = nil
	return p
}

func TestDAGRecoveredPreparationFixture(t *testing.T) {
	p, _, next := b3Preparation(t, dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", "", nil, nil), "https://synthetic.example.invalid")
	if e := ValidateDAGRecoveredPromotion(p, next); e != nil {
		t.Fatal("valid signed promotion prerequisite", e)
	}
}

func TestDAGRecoveredPreparationStrictColdShape(t *testing.T) {
	p, _, _ := b3Preparation(t, dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", "", nil, nil), "https://synthetic.example.invalid")
	for _, v := range []DAGRecoveredPreparation{b3Intent(p), p} {
		raw, _ := json.Marshal(v)
		if _, e := DecodeDAGRecoveredPreparation(raw); e != nil {
			t.Fatal(e)
		}
	}
	clone := func() DAGRecoveredPreparation {
		raw, _ := json.Marshal(p)
		v, e := DecodeDAGRecoveredPreparation(raw)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	edits := map[string]func(*DAGRecoveredPreparation){
		"kind":          func(p *DAGRecoveredPreparation) { p.Kind = "transition-v2" },
		"root":          func(p *DAGRecoveredPreparation) { p.Pin.DeviceID = "different" },
		"init-hash":     func(p *DAGRecoveredPreparation) { p.InitializationHash = string(make([]byte, 64)) },
		"init-proposal": func(p *DAGRecoveredPreparation) { p.InitializationProposalHash = p.RecoveryHeadHash },
		"session": func(p *DAGRecoveredPreparation) {
			p.RestrictedSessionHash = p.InitializationHash
			p.Challenge.RestrictedSessionHash = p.RestrictedSessionHash
		},
		"recovery-head":        func(p *DAGRecoveredPreparation) { p.RecoveryHeadHash = p.InitializationHash },
		"recovery-key":         func(p *DAGRecoveredPreparation) { p.RecoverySigningPublicKey = p.DeviceSigningPublicKey },
		"recovery-gen":         func(p *DAGRecoveredPreparation) { p.RecoveryGeneration = "4" },
		"device-key-collision": func(p *DAGRecoveredPreparation) { p.DeviceSigningPublicKey = p.RecoverySigningPublicKey },
		"prior-id":             func(p *DAGRecoveredPreparation) { p.PriorOperationID = "other-original" },
		"prior-hash":           func(p *DAGRecoveredPreparation) { p.PriorContentHash = p.InitializationHash },
		"prior-sequence":       func(p *DAGRecoveredPreparation) { p.PriorAcceptedSequence++ },
		"before-prior":         func(p *DAGRecoveredPreparation) { p.ExpectedSequence = 1 },
		"bundle-signature": func(p *DAGRecoveredPreparation) {
			p.BaseBundle.Records[2].TransitionV2.Submission.NewRecoverySignature = "bad"
		},
		"empty-rights":    func(p *DAGRecoveredPreparation) { p.SelectedRights = nil },
		"role":            func(p *DAGRecoveredPreparation) { p.SelectedRights[0].Role = "owner" },
		"negative-expiry": func(p *DAGRecoveredPreparation) { p.SelectedRights[0].ExpiresAt = "-1" },
		"version": func(p *DAGRecoveredPreparation) {
			p.SelectedRights[0].KeyVersion = "99"
			p.SelectedRightsHash, _ = cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
		},
		"rights-hash":       func(p *DAGRecoveredPreparation) { p.SelectedRightsHash = p.InitializationHash },
		"manifest":          func(p *DAGRecoveredPreparation) { p.EnvironmentManifest = nil },
		"challenge-session": func(p *DAGRecoveredPreparation) { p.Challenge.RestrictedSessionHash = p.InitializationHash },
		"challenge-basis":   func(p *DAGRecoveredPreparation) { p.Challenge.ExpectedSequence = "999" },
		"challenge-key":     func(p *DAGRecoveredPreparation) { p.Challenge.DeviceSigningPublicKey = p.RecoverySigningPublicKey },
		"challenge-bundle":  func(p *DAGRecoveredPreparation) { p.Challenge.DependencyBundle.Records = nil },
		"challenge-source":  func(p *DAGRecoveredPreparation) { p.Challenge.IssuerEvidence.View.RecoveryHeadHash = "wrong" },
		"challenge-nonce":   func(p *DAGRecoveredPreparation) { p.Challenge.Nonce = "wrong" },
		"phase":             func(p *DAGRecoveredPreparation) { p.Phase = "sealed" },
		"mixed-intent":      func(p *DAGRecoveredPreparation) { p.Phase = "intent" },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			v := clone()
			edit(&v)
			raw, _ := json.Marshal(v)
			if _, e := DecodeDAGRecoveredPreparation(raw); e == nil {
				t.Fatal("invalid public identity/selection accepted")
			}
		})
	}
	raw, _ := json.Marshal(p)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for name := range fields {
		for _, null := range []bool{false, true} {
			t.Run("required/"+name+strconv.FormatBool(null), func(t *testing.T) {
				var m map[string]json.RawMessage
				_ = json.Unmarshal(raw, &m)
				if null {
					m[name] = json.RawMessage(`null`)
				} else {
					delete(m, name)
				}
				b, _ := json.Marshal(m)
				if _, e := DecodeDAGRecoveredPreparation(b); e == nil {
					t.Fatal("missing/null required field accepted")
				}
			})
		}
	}
	for _, b := range [][]byte{append([]byte(`{"version":1,`), raw[1:]...), append(append([]byte{}, raw...), []byte(` {}`)...), append([]byte(`{"unexpected":false,`), raw[1:]...), make([]byte, MaxDAGPreparationBytes+1)} {
		if _, e := DecodeDAGRecoveredPreparation(b); e == nil {
			t.Fatal("duplicate/unknown/trailing/oversize accepted")
		}
	}
	p.Challenge.ExpiresAt = 1
	if e := ValidateDAGRecoveredPreparation(p); e != nil {
		t.Fatal("historical expiry must remain queryable metadata", e)
	}
}
func TestDAGRecoveredPreparationPromotionExactSelection(t *testing.T) {
	p, _, next := b3Preparation(t, dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", "", nil, nil), "https://synthetic.example.invalid")
	for name, edit := range map[string]func(*DAGRecoveredPreparation){
		"id": func(p *DAGRecoveredPreparation) {
			p.OperationID = "other-original"
			p.Challenge.OperationID = p.OperationID
		},
		"nonce":     func(p *DAGRecoveredPreparation) { p.Challenge.Nonce = cryptox.EncodeBase64(make([]byte, 32)) },
		"challenge": func(p *DAGRecoveredPreparation) { p.Challenge.ChallengeID = "other-challenge" },
		"expiry":    func(p *DAGRecoveredPreparation) { p.Challenge.ExpiresAt++ },
		"sequence": func(p *DAGRecoveredPreparation) {
			p.ExpectedSequence++
			p.Challenge.ExpectedSequence = strconv.FormatUint(p.ExpectedSequence, 10)
		},
		"role": func(p *DAGRecoveredPreparation) {
			p.SelectedRights[0].Role = "ro"
			p.SelectedRightsHash, _ = cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
		},
		"right-expiry": func(p *DAGRecoveredPreparation) {
			p.SelectedRights[0].ExpiresAt = "0"
			p.SelectedRightsHash, _ = cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
		},
		"environment-subset": func(p *DAGRecoveredPreparation) {
			p.SelectedRights = p.SelectedRights[1:]
			p.SelectedRightsHash, _ = cryptox.RecoveredDeviceRightsHash(p.SelectedRights)
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			v, e := DecodeDAGRecoveredPreparation(raw)
			if e != nil {
				t.Fatal(e)
			}
			edit(&v)
			if e = ValidateDAGRecoveredPreparation(v); e != nil {
				t.Fatal("negative must reach promotion with valid preparation", e)
			}
			if e = ValidateDAGRecoveredPromotion(v, next); e == nil {
				t.Fatal("different intent promoted")
			}
		})
	}
	if !DAGRecoveredPreparationSameIntent(b3Intent(p), p) {
		t.Fatal("phase changed intent")
	}
}

func TestB3aReviewStrictNestedFields(t *testing.T) {
	p, _, _ := b3Preparation(t, dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", "", nil, nil), "https://synthetic.example.invalid")
	raw, _ := json.Marshal(p)
	for _, mode := range []string{"case-alias", "semantic-duplicate"} {
		t.Run(mode, func(t *testing.T) {
			var outer map[string]json.RawMessage
			_ = json.Unmarshal(raw, &outer)
			var rights []map[string]json.RawMessage
			_ = json.Unmarshal(outer["selectedRights"], &rights)
			rights[0]["Role"] = rights[0]["role"]
			if mode == "case-alias" {
				delete(rights[0], "role")
			}
			outer["selectedRights"], _ = json.Marshal(rights)
			input, _ := json.Marshal(outer)
			if _, err := DecodeDAGRecoveredPreparation(input); err == nil {
				t.Fatal("nested non-schema Role field accepted")
			}
		})
	}
}

// Every nested object is exercised through the public decoder; each field also
// receives exact-name/presence/null probes against its independently validated
// canonical wire shape. No changed field value or invalid signature is needed
// to make the alias negatives fail.
func TestB3aEveryNestedObjectExactSchema(t *testing.T) {
	p, _, _ := b3Preparation(t, dagrecoveredfixture.Load(t, "../cryptox/testdata/recovery-dag-v1.json", "", nil, nil), "https://synthetic.example.invalid")
	raw, _ := json.Marshal(p)
	if _, e := DecodeDAGRecoveredPreparation(raw); e != nil {
		t.Fatal("valid signed full schema prerequisite", e)
	}
	decode := func(raw []byte) any {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var v any
		if e := d.Decode(&v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	canonical := decode(raw)
	type object struct {
		path  []any
		value map[string]any
	}
	var objects []object
	var collect func(any, []any)
	collect = func(v any, path []any) {
		switch x := v.(type) {
		case map[string]any:
			if len(path) > 0 {
				objects = append(objects, object{append([]any(nil), path...), x})
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				collect(x[k], append(append([]any(nil), path...), k))
			}
		case []any:
			for i, v := range x {
				collect(v, append(append([]any(nil), path...), i))
			}
		}
	}
	collect(canonical, nil)
	locate := func(doc any, path []any) map[string]any {
		v := doc
		for _, part := range path {
			switch k := part.(type) {
			case string:
				v = v.(map[string]any)[k]
			case int:
				v = v.([]any)[k]
			}
		}
		return v.(map[string]any)
	}
	alias := func(key string) string {
		first := key[0]
		if first >= 'a' && first <= 'z' {
			return string(first-'a'+'A') + key[1:]
		}
		if first >= 'A' && first <= 'Z' {
			return string(first-'A'+'a') + key[1:]
		}
		t.Fatal("schema field must have alphabetic initial")
		return ""
	}
	integration, fieldChecks, canonicalNulls := 0, 0, 0
	for _, o := range objects {
		keys := make([]string, 0, len(o.value))
		for k := range o.value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			t.Fatal("unexpected empty canonical object")
		}
		for _, mode := range []string{"alias", "duplicate"} {
			doc := decode(raw)
			m := locate(doc, o.path)
			key := keys[0]
			m[alias(key)] = m[key]
			if mode == "alias" {
				delete(m, key)
			}
			input, _ := json.Marshal(doc)
			if _, e := DecodeDAGRecoveredPreparation(input); e == nil {
				t.Fatalf("nested %s accepted at %v.%s", mode, o.path, key)
			}
			integration++
		}
		for _, key := range keys {
			for _, mode := range []string{"alias", "duplicate", "missing", "null"} {
				altered := make(map[string]any, len(o.value)+1)
				for k, v := range o.value {
					altered[k] = v
				}
				switch mode {
				case "alias":
					altered[alias(key)] = altered[key]
					delete(altered, key)
				case "duplicate":
					altered[alias(key)] = altered[key]
				case "missing":
					delete(altered, key)
				case "null":
					if o.value[key] == nil {
						canonicalNulls++
						continue
					}
					altered[key] = nil
				}
				if sameDAGRecoveredJSONShape(altered, o.value, 1) {
					t.Fatalf("nested field shape %s accepted at %v.%s", mode, o.path, key)
				}
				fieldChecks++
			}
		}
	}
	if len(objects) < 30 || integration < 60 || fieldChecks < 150 || canonicalNulls == 0 {
		t.Fatal("nested/nullable fixture coverage unexpectedly shrank", len(objects), integration, fieldChecks, canonicalNulls)
	}
	for _, value := range []DAGRecoveredPreparation{b3Intent(p), p} {
		b, _ := json.Marshal(value)
		if _, e := DecodeDAGRecoveredPreparation(b); e != nil {
			t.Fatal("legal nullable/omitted optional fields changed", e)
		}
	}
	// Challenge is omitempty in intent, not an arbitrary nullable permission.
	var intent map[string]json.RawMessage
	b, _ := json.Marshal(b3Intent(p))
	_ = json.Unmarshal(b, &intent)
	intent["challenge"] = json.RawMessage(`null`)
	b, _ = json.Marshal(intent)
	if _, e := DecodeDAGRecoveredPreparation(b); e == nil {
		t.Fatal("unexpected optional null accepted")
	}
	t.Logf("B3A_NESTED_SCHEMA_COUNTS objects=%d decoderAliasNegatives=%d fieldShapeNegatives=%d preservedCanonicalNulls=%d", len(objects), integration, fieldChecks, canonicalNulls)
}
