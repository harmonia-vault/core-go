package cryptox

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRecoveryOperationResolutionPublishedBytes(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("testdata", "recovery-operation-resolution-v1.json"))
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		CurrentSessionHash string `json:"currentSessionHash"`
		Requests           []struct {
			Request             RecoveryOperationResolutionRequest `json:"request"`
			TargetHash          string                             `json:"targetHash"`
			TargetCanonicalHex  string                             `json:"targetCanonicalHex"`
			SigningCanonicalHex string                             `json:"signingCanonicalHex"`
		} `json:"requests"`
		Receipts            map[string]json.RawMessage `json:"receipts"`
		TransitionChallenge struct {
			AccountID           string `json:"accountId"`
			ChallengeHash       string `json:"challengeHash"`
			DependencyBasisHash string `json:"dependencyBasisHash"`
			Challenge           struct {
				OperationID, ChallengeID, Nonce, SessionHash, AccountGeneration, AuthorizationKind, ChainMode, AuthorizerDeviceID, ExpectedSequence, PreviousTransitionHash, OldRecoveryGeneration, OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey string
				ExpiresAt                                                                                                                                                                                                                                      int64
				EnvironmentManifest                                                                                                                                                                                                                            []RecoveryEnvironmentVersion
				AuthoritySet                                                                                                                                                                                                                                   []RecoveryAdminAuthority
				IssuerEvidence                                                                                                                                                                                                                                 *RecoverySource
				DependencyBundle                                                                                                                                                                                                                               RecoveryDependencyBundle
			} `json:"challenge"`
		} `json:"transitionChallenge"`
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	for _, item := range f.Requests {
		b, e := item.Request.Target.CanonicalBytes()
		if e != nil || hex.EncodeToString(b) != item.TargetCanonicalHex {
			t.Fatal("target vector mismatch", e)
		}
		h, e := item.Request.Target.Hash()
		if e != nil || h != item.TargetHash {
			t.Fatal("target hash mismatch", e)
		}
		b, e = RecoveryOperationResolutionSigningBytes(item.Request.Target, item.Request.Mode, f.CurrentSessionHash)
		if e != nil || hex.EncodeToString(b) != item.SigningCanonicalHex || VerifyRecoveryOperationResolution(item.Request, f.CurrentSessionHash) != nil {
			t.Fatal("signature vector mismatch", e)
		}
	}
	c := f.TransitionChallenge.Challenge
	hash, e := RecoveryOperationTransitionChallengeHash(RecoveryOperationTransitionChallenge{AccountID: f.TransitionChallenge.AccountID, AccountGeneration: c.AccountGeneration, OperationID: c.OperationID, ChallengeID: c.ChallengeID, Nonce: c.Nonce, ExpiresAt: strconv.FormatInt(c.ExpiresAt, 10), SessionHash: c.SessionHash, AuthorizationKind: c.AuthorizationKind, ChainMode: c.ChainMode, AuthorizerDeviceID: c.AuthorizerDeviceID, ExpectedSequence: c.ExpectedSequence, PreviousTransitionHash: c.PreviousTransitionHash, OldRecoveryGeneration: c.OldRecoveryGeneration, OldRecoverySigningPublicKey: c.OldRecoverySigningPublicKey, OldRecoveryReceivingPublicKey: c.OldRecoveryReceivingPublicKey, EnvironmentManifest: c.EnvironmentManifest, AuthoritySet: c.AuthoritySet, IssuerEvidence: c.IssuerEvidence, DependencyBundle: c.DependencyBundle})
	if e != nil || hash != f.TransitionChallenge.ChallengeHash {
		t.Fatal("challenge vector mismatch", e)
	}
	hash, e = RecoveryOperationDependencyBasisHash(c.DependencyBundle)
	if e != nil || hash != f.TransitionChallenge.DependencyBasisHash {
		t.Fatal("basis vector mismatch", e)
	}
	for _, raw := range f.Receipts {
		if _, e = DecodeRecoveryOperationResolutionReceipt(raw); e != nil {
			t.Fatal("receipt vector", e)
		}
	}
}
func TestRecoveryOperationReceiptExactShape(t *testing.T) {
	target := RecoveryOperationTarget{Profile: RecoveryDAGCapability, Kind: "transition-v2", AccountID: "synthetic-account", AccountGeneration: "1", OperationID: "original-op", OriginalSessionHash: stringRepeat("1", 64), AuthorizationKind: "old-recovery", DeviceID: "synthetic-device", DeviceSigningPublicKey: EncodeBase64(make([]byte, 32)), DeviceReceivingPublicKey: EncodeBase64(append([]byte{1}, make([]byte, 31)...)), Stage: "sealed", Basis: RecoveryOperationBasis{InitializationHash: stringRepeat("2", 64), ExpectedSequence: "1", RecoveryGeneration: "1", RecoveryHeadHash: stringRepeat("3", 64), RecoverySigningPublicKey: EncodeBase64(append([]byte{2}, make([]byte, 31)...)), RecoveryReceivingPublicKey: EncodeBase64(append([]byte{3}, make([]byte, 31)...)), DependencyBundleHash: stringRepeat("4", 64), EnvironmentManifestHash: stringRepeat("5", 64)}, DeclaredIntentHash: stringRepeat("6", 64), KnownChallengeHash: stringRepeat("7", 64), DeclaredContentHash: stringRepeat("8", 64)}
	h, e := target.Hash()
	if e != nil {
		t.Fatal(e)
	}
	known := target.KnownChallengeHash
	receipt := RecoveryOperationResolutionReceipt{Version: 1, Profile: RecoveryOperationResolutionProfile, AccountID: target.AccountID, AccountGeneration: "1", Kind: target.Kind, OperationID: target.OperationID, TargetHash: h, State: "closed", Sequence: 2, ObservedChallengeHash: &known}
	good, e := json.Marshal(receipt)
	if e != nil || receipt.ValidateTarget(target) != nil {
		t.Fatal("valid closed", e)
	}
	for _, mutate := range []func(map[string]any){func(m map[string]any) { delete(m, "observedChallengeHash") }, func(m map[string]any) { m["contentHash"] = target.DeclaredContentHash }, func(m map[string]any) { m["Sequence"] = m["sequence"]; delete(m, "sequence") }, func(m map[string]any) { m["sequence"] = nil }, func(m map[string]any) { m["observedChallengeHash"] = 42 }, func(m map[string]any) { m["targetHash"] = "" }} {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		mutate(m)
		raw, _ := json.Marshal(m)
		if _, e = DecodeRecoveryOperationResolutionReceipt(raw); e == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	receipt.ObservedChallengeHash = nil
	if receipt.ValidateTarget(target) == nil {
		t.Fatal("sealed missing challenge accepted")
	}
	receipt.ObservedChallengeHash = &known
	receipt.Sequence = 1
	if receipt.ValidateTarget(target) == nil {
		t.Fatal("closed rollback accepted")
	}
}
func stringRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
