package syncclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

var ErrFullPullRequired = errors.New("new authorization requires full durable history")

// PinnedTrust 只能由受信任手机确认/完整恢复流程提供；没有从服务器公钥
// 自动建立信任的入口。当前正式 enrollment 未完成，CLI 不接受此结构。
type PinnedTrust struct {
	AccountID              string
	AccountGeneration      uint64
	DeviceID               string
	DeviceSigningPublicKey ed25519.PublicKey
	ReceivingPrivateKey    []byte
	Managers               map[string]ed25519.PublicKey
	Now                    func() time.Time
}
type PinnedVerifier struct {
	trust              PinnedTrust
	receivingPublicKey string
}

func NewPinnedVerifier(trust PinnedTrust) (*PinnedVerifier, error) {
	if trust.AccountID == "" || trust.AccountGeneration == 0 || trust.DeviceID == "" || len(trust.DeviceSigningPublicKey) != ed25519.PublicKeySize || len(trust.Managers) == 0 {
		return nil, errors.New("incomplete trusted context")
	}
	sk, err := ecdh.X25519().NewPrivateKey(trust.ReceivingPrivateKey)
	if err != nil {
		return nil, errors.New("invalid trusted receiving key")
	}
	trust.ReceivingPrivateKey = bytes.Clone(trust.ReceivingPrivateKey)
	trust.DeviceSigningPublicKey = bytes.Clone(trust.DeviceSigningPublicKey)
	managers := map[string]ed25519.PublicKey{}
	for id, key := range trust.Managers {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid pinned manager key")
		}
		managers[id] = bytes.Clone(key)
	}
	trust.Managers = managers
	if trust.Now == nil {
		trust.Now = time.Now
	}
	return &PinnedVerifier{trust: trust, receivingPublicKey: cryptox.EncodeBase64(sk.PublicKey().Bytes())}, nil
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func copyMap[T any](in map[string]T) map[string]T {
	out := map[string]T{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func parsePositive(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
		return 0, cryptox.ErrInvalidWire
	}
	return n, nil
}
func (v *PinnedVerifier) verifyGrant(signed SignedGrant) error {
	grant := signed.Grant
	if grant.AccountID != v.trust.AccountID || grant.AccountGeneration != strconv.FormatUint(v.trust.AccountGeneration, 10) {
		return errors.New("grant account/generation mismatch")
	}
	key, ok := v.trust.Managers[grant.IssuerDeviceID]
	if !ok {
		return errors.New("grant issuer is not a pinned trusted manager")
	}
	return cryptox.VerifyGrant(cryptox.SignedGrant{Grant: grant, Signature: signed.Signature}, key)
}
func (v *PinnedVerifier) VerifyPull(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return localstate.CloudSnapshot{}, err
	}
	generation := strconv.FormatUint(v.trust.AccountGeneration, 10)
	if pull.AccountID != v.trust.AccountID || pull.AccountGeneration != generation || pull.Sequence < previous.Sequence {
		return localstate.CloudSnapshot{}, errors.New("unbound/replayed checkpoint")
	}
	if previous.AccountID != "" && (previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration) {
		return localstate.CloudSnapshot{}, errors.New("trusted context belongs to another account generation")
	}
	out := localstate.CloudSnapshot{AccountID: pull.AccountID, AccountGeneration: v.trust.AccountGeneration, Sequence: pull.Sequence, Environments: map[string]localstate.Environment{}, GrantCheckpoints: copyMap(previous.GrantCheckpoints), GrantFingerprints: copyMap(previous.GrantFingerprints), SeenMutations: copyMap(previous.SeenMutations)}
	environmentKeys := map[string][]byte{}
	seenGrant := map[string]bool{}
	now := v.trust.Now()
	for _, signed := range pull.Grants {
		if err := v.verifyGrant(signed); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		g := signed.Grant
		if g.SubjectDeviceID != v.trust.DeviceID || g.SubjectSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || g.SubjectReceivingPublicKey != v.receivingPublicKey {
			return localstate.CloudSnapshot{}, errors.New("grant does not bind the exact local device keys")
		}
		if seenGrant[g.EnvironmentID] {
			return localstate.CloudSnapshot{}, errors.New("duplicate current environment grant")
		}
		seenGrant[g.EnvironmentID] = true
		grantGeneration, err := parsePositive(g.GrantGeneration)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		keyVersion, err := parsePositive(g.KeyVersion)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		signingBytes, _ := g.SigningBytes()
		fingerprint := digest(signingBytes)
		if highest := out.GrantCheckpoints[g.EnvironmentID]; grantGeneration < highest || (grantGeneration == highest && out.GrantFingerprints[g.EnvironmentID] != "" && out.GrantFingerprints[g.EnvironmentID] != fingerprint) {
			return localstate.CloudSnapshot{}, errors.New("grant generation replay or same-generation equivocation")
		}
		out.GrantCheckpoints[g.EnvironmentID] = grantGeneration
		out.GrantFingerprints[g.EnvironmentID] = fingerprint
		expiry, err := strconv.ParseUint(g.ExpiresAt, 10, 64)
		if err != nil || expiry > math.MaxInt64 {
			return localstate.CloudSnapshot{}, errors.New("invalid authorization expiry")
		}
		if g.Role == "none" || (expiry != 0 && !now.Before(time.Unix(int64(expiry), 0))) {
			continue
		}
		old, exists := previous.Environments[g.EnvironmentID]
		if exists && keyVersion < old.KeyVersion {
			return localstate.CloudSnapshot{}, errors.New("environment key version moved backwards")
		}
		if previous.Sequence > 0 && !pull.Full && (!exists || old.KeyVersion != keyVersion) {
			return localstate.CloudSnapshot{}, ErrFullPullRequired
		}
		packet, err := cryptox.DecodeBase64(g.Envelope, 80, 80)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		key, err := cryptox.UnwrapEnvironmentKey(v.trust.ReceivingPrivateKey, cryptox.EnvelopeContext{AccountID: g.AccountID, AccountGeneration: g.AccountGeneration, EnvironmentID: g.EnvironmentID, KeyVersion: g.KeyVersion, RecipientType: "device", RecipientID: g.SubjectDeviceID, RecipientGeneration: g.GrantGeneration, RecipientPublicKey: g.SubjectReceivingPublicKey}, packet)
		if err != nil {
			return localstate.CloudSnapshot{}, errors.New("trusted environment envelope failed to open")
		}
		environmentKeys[g.EnvironmentID] = key
		role := localstate.ReadOnly
		if g.Role == "rw" {
			role = localstate.ReadWrite
		} else if g.Role == "admin" {
			role = localstate.Admin
		}
		environment := localstate.Environment{ID: g.EnvironmentID, KeyVersion: keyVersion, GrantGeneration: grantGeneration, Role: role, Values: map[string]string{}}
		if expiry != 0 {
			expires := time.Unix(int64(expiry), 0)
			environment.ExpiresAt = &expires
		}
		if !pull.Full && exists && old.KeyVersion == keyVersion {
			environment.Values = copyMap(old.Values)
		}
		out.Environments[g.EnvironmentID] = environment
	}
	responseSeen := map[string]bool{}
	last := previous.Sequence
	if pull.Full {
		last = 0
	}
	for _, event := range pull.Events {
		if err := ctx.Err(); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		if event.Sequence <= last || event.Sequence > pull.Sequence {
			return localstate.CloudSnapshot{}, errors.New("unordered/replayed event")
		}
		last = event.Sequence
		m := event.Mutation.Mutation
		authorization := event.Authorization
		if authorization == nil {
			return localstate.CloudSnapshot{}, errors.New("mutation lacks its signed writer authorization")
		}
		if err := v.verifyGrant(*authorization); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		g := authorization.Grant
		if m.AccountID != pull.AccountID || m.AccountGeneration != generation || g.SubjectDeviceID != m.DeviceID || g.EnvironmentID != m.EnvironmentID || g.KeyVersion != m.KeyVersion || g.GrantGeneration != m.GrantGeneration || (g.Role != "rw" && g.Role != "admin") {
			return localstate.CloudSnapshot{}, errors.New("mutation does not match signed writable authorization")
		}
		signingKey, err := cryptox.DecodeBase64(g.SubjectSigningPublicKey, 32, 32)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		if err = cryptox.VerifyMutation(cryptox.SignedMutation{Mutation: m, Signature: event.Mutation.Signature}, ed25519.PublicKey(signingKey)); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		wire, _ := m.SigningBytes()
		id := m.DeviceID + "/" + m.IdempotencyKey
		fingerprint := digest(wire)
		if responseSeen[id] {
			return localstate.CloudSnapshot{}, errors.New("duplicate idempotency key in one pull response")
		}
		responseSeen[id] = true
		if old, ok := out.SeenMutations[id]; ok {
			if !pull.Full || event.Sequence != old.Sequence || old.Fingerprint != fingerprint {
				return localstate.CloudSnapshot{}, errors.New("signed mutation idempotency key replayed at a new sequence")
			}
		}
		out.SeenMutations[id] = localstate.MutationCheckpoint{Sequence: event.Sequence, Fingerprint: fingerprint}
		environment, readable := out.Environments[m.EnvironmentID]
		if !readable {
			return localstate.CloudSnapshot{}, errors.New("event exposed an unauthorized environment")
		}
		keyVersion, err := parsePositive(m.KeyVersion)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		if keyVersion != environment.KeyVersion {
			if pull.Full && keyVersion < environment.KeyVersion {
				continue
			}
			return localstate.CloudSnapshot{}, errors.New("mutation key version mismatch")
		}
		switch m.Operation {
		case "delete":
			delete(environment.Values, m.Name)
		case "put":
			packet, err := cryptox.DecodeBase64(m.Payload, 40, cryptox.MaxValueBytes+40)
			if err != nil {
				return localstate.CloudSnapshot{}, err
			}
			plaintext, err := cryptox.DecryptValue(environmentKeys[m.EnvironmentID], cryptox.ValueContext{AccountID: m.AccountID, AccountGeneration: m.AccountGeneration, EnvironmentID: m.EnvironmentID, KeyVersion: m.KeyVersion, Name: m.Name}, packet)
			if err != nil {
				return localstate.CloudSnapshot{}, fmt.Errorf("environment value authentication failed: %w", err)
			}
			environment.Values[m.Name] = string(plaintext)
		default:
			return localstate.CloudSnapshot{}, cryptox.ErrInvalidWire
		}
		out.Environments[m.EnvironmentID] = environment
	}
	return out, nil
}
