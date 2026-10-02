package syncclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

type EnvironmentEvent struct {
	Sequence      uint64                          `json:"sequence"`
	Change        cryptox.SignedEnvironmentChange `json:"change"`
	Authorization SignedGrant                     `json:"authorization"`
	Subjects      []string                        `json:"subjects"`
}

func (v *PinnedVerifier) verifyEnvironmentEvents(ctx context.Context, pull Pull, previous localstate.CloudSnapshot, out *localstate.CloudSnapshot) error {
	out.EnvironmentCheckpoints = copyMap(previous.EnvironmentCheckpoints)
	out.DeletedEnvironments = copyMap(previous.DeletedEnvironments)
	seen := map[string]bool{}
	var last uint64
	for _, event := range pull.EnvironmentEvents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if event.Sequence == 0 || event.Sequence <= last || event.Sequence > pull.Sequence {
			return errors.New("unordered environment lifecycle event")
		}
		last = event.Sequence
		c := event.Change.Change
		g := event.Authorization.Grant
		if c.AccountID != pull.AccountID || c.AccountGeneration != pull.AccountGeneration || g.AccountID != c.AccountID || g.AccountGeneration != c.AccountGeneration || g.SubjectDeviceID != c.DeviceID || g.EnvironmentID != c.AuthorityEnvironmentID || g.KeyVersion != c.AuthorityKeyVersion || g.GrantGeneration != c.AuthorityGrantGeneration || g.Role != "admin" {
			return errors.New("environment operation does not bind prior signed admin authority")
		}
		if err := v.verifyGrant(event.Authorization); err != nil {
			return err
		}
		signer, err := cryptox.DecodeBase64(g.SubjectSigningPublicKey, 32, 32)
		if err != nil {
			return err
		}
		public := ed25519.PublicKey(signer)
		if err = cryptox.VerifyEnvironmentChange(event.Change, public); err != nil {
			return err
		}
		expected, err := strconv.ParseUint(c.ExpectedSequence, 10, 64)
		if err != nil || expected >= 9007199254740991 || event.Sequence != expected+1 {
			return errors.New("environment sequence is not bound to signed expected checkpoint")
		}
		id := c.DeviceID + "/" + c.IdempotencyKey
		wire, _ := c.SigningBytes()
		fingerprint := digest(wire)
		if seen[id] {
			return errors.New("duplicate environment idempotency key")
		}
		seen[id] = true
		if old, exists := out.EnvironmentCheckpoints[id]; exists && (old.Sequence != event.Sequence || old.Fingerprint != fingerprint) {
			return errors.New("environment event replayed at different checkpoint")
		}
		out.EnvironmentCheckpoints[id] = localstate.MutationCheckpoint{Sequence: event.Sequence, Fingerprint: fingerprint}
		previousVersion, err := strconv.ParseUint(c.PreviousKeyVersion, 10, 64)
		if err != nil {
			return err
		}
		version, err := parsePositive(c.KeyVersion)
		if err != nil {
			return err
		}
		switch c.Operation {
		case "create":
			if previousVersion != 0 || version != 1 {
				return errors.New("invalid new environment version")
			}
			if deleted := out.DeletedEnvironments[c.EnvironmentID]; deleted != 0 && event.Sequence > deleted {
				return errors.New("deleted environment ID was reused")
			}
		case "rotate":
			if previousVersion == 0 || previousVersion == ^uint64(0) || version != previousVersion+1 || c.AuthorityEnvironmentID != c.EnvironmentID {
				return errors.New("invalid environment rotation version")
			}
		case "rename", "delete":
			if previousVersion == 0 || version != previousVersion || c.AuthorityEnvironmentID != c.EnvironmentID {
				return errors.New("invalid environment metadata version")
			}
		default:
			return errors.New("unknown environment operation")
		}
		if c.Operation == "create" || c.Operation == "rotate" {
			for _, signed := range c.Grants {
				grant := signed.Grant
				if grant.AccountID != c.AccountID || grant.AccountGeneration != c.AccountGeneration || grant.EnvironmentID != c.EnvironmentID || grant.KeyVersion != c.KeyVersion || grant.IssuerDeviceID != c.DeviceID {
					return errors.New("environment grant manifest binding mismatch")
				}
				if err = cryptox.VerifyGrant(signed.SignedGrant(), public); err != nil {
					return err
				}
			}
			for _, signed := range c.Mutations {
				mutation := signed.Mutation
				if mutation.AccountID != c.AccountID || mutation.AccountGeneration != c.AccountGeneration || mutation.EnvironmentID != c.EnvironmentID || mutation.KeyVersion != c.KeyVersion || mutation.DeviceID != c.DeviceID || mutation.Operation != "put" {
					return errors.New("rotation mutation manifest binding mismatch")
				}
				author := false
				for _, grant := range c.Grants {
					if grant.Grant.SubjectDeviceID == mutation.DeviceID && grant.Grant.GrantGeneration == mutation.GrantGeneration && (grant.Grant.Role == "admin" || grant.Grant.Role == "rw") {
						author = true
					}
				}
				if !author {
					return errors.New("rotation manifest lacks signed writable grant")
				}
				if err = cryptox.VerifyMutation(signed.SignedMutation(), public); err != nil {
					return err
				}
			}
		}
		if c.Operation == "delete" {
			if event.Sequence > out.DeletedEnvironments[c.EnvironmentID] {
				out.DeletedEnvironments[c.EnvironmentID] = event.Sequence
			}
		}
	}
	return nil
}
