package syncclient

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

func (v *PinnedVerifier) VerifyAuthorizationRefresh(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if previous.AccountID != "" && (previous.AccountID != v.trust.AccountID || previous.AccountGeneration != v.trust.AccountGeneration) {
		return localstate.CloudSnapshot{}, errors.New("authorization context belongs to another account generation")
	}
	if pull.Sequence > 9007199254740991 {
		return localstate.CloudSnapshot{}, errors.New("invalid authorization checkpoint")
	}
	if pull.Scope != "authorizations" || len(pull.Events) != 0 || pull.AccountID != v.trust.AccountID || pull.AccountGeneration != strconv.FormatUint(v.trust.AccountGeneration, 10) || pull.Sequence < previous.Sequence || pull.Sequence < previous.AuthorizationSequence {
		return localstate.CloudSnapshot{}, errors.New("unbound authorization projection")
	}
	out := previous
	out.AccountID = pull.AccountID
	out.AccountGeneration = v.trust.AccountGeneration
	out.AuthorizationSequence = pull.Sequence
	out.Environments = map[string]localstate.Environment{}
	out.GrantCheckpoints = copyMap(previous.GrantCheckpoints)
	out.GrantFingerprints = copyMap(previous.GrantFingerprints)
	if err := v.verifyEnvironmentEvents(ctx, pull, previous, &out); err != nil {
		return localstate.CloudSnapshot{}, err
	}
	seen := map[string]bool{}
	now := v.trust.Now()
	for _, signed := range pull.Grants {
		if err := ctx.Err(); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		if err := v.verifyGrant(signed); err != nil {
			return localstate.CloudSnapshot{}, err
		}
		g := signed.Grant
		if g.SubjectDeviceID != v.trust.DeviceID || g.SubjectSigningPublicKey != cryptox.EncodeBase64(v.trust.DeviceSigningPublicKey) || g.SubjectReceivingPublicKey != v.receivingPublicKey || seen[g.EnvironmentID] || out.DeletedEnvironments[g.EnvironmentID] != 0 {
			return localstate.CloudSnapshot{}, errors.New("authorization projection key/subject/tombstone mismatch")
		}
		seen[g.EnvironmentID] = true
		generation, err := parsePositive(g.GrantGeneration)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		keyVersion, err := parsePositive(g.KeyVersion)
		if err != nil {
			return localstate.CloudSnapshot{}, err
		}
		wire, _ := g.SigningBytes()
		fingerprint := digest(wire)
		highest := out.GrantCheckpoints[g.EnvironmentID]
		if generation < highest || generation == highest && out.GrantFingerprints[g.EnvironmentID] != "" && out.GrantFingerprints[g.EnvironmentID] != fingerprint {
			return localstate.CloudSnapshot{}, errors.New("authorization generation moved backwards or equivocated")
		}
		out.GrantCheckpoints[g.EnvironmentID] = generation
		out.GrantFingerprints[g.EnvironmentID] = fingerprint
		expiry, err := strconv.ParseUint(g.ExpiresAt, 10, 64)
		if err != nil || expiry > math.MaxInt64 {
			return localstate.CloudSnapshot{}, errors.New("invalid authorization expiry")
		}
		old, exists := previous.Environments[g.EnvironmentID]
		if !exists || g.Role == "none" || expiry != 0 && !now.Before(time.Unix(int64(expiry), 0)) || old.KeyVersion != keyVersion {
			continue
		}
		old.Values = copyMap(old.Values)
		old.GrantGeneration = generation
		if g.Role == "ro" {
			old.Role = localstate.ReadOnly
		} else if g.Role == "rw" && old.Role == localstate.Admin {
			old.Role = localstate.ReadWrite
		}
		if expiry != 0 {
			next := time.Unix(int64(expiry), 0)
			if old.ExpiresAt == nil || next.Before(*old.ExpiresAt) {
				old.ExpiresAt = &next
			}
		}
		out.Environments[g.EnvironmentID] = old
	}
	return out, nil
}
func (c *Client) RefreshAuthorizations(ctx context.Context) (Pull, error) {
	previous := c.config.Engine.State().Cloud
	verifier, ok := c.config.Verifier.(interface {
		VerifyAuthorizationRefresh(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error)
	})
	if !ok {
		return Pull{}, errors.New("authorization projection requires pinned permission verification")
	}
	after := previous.AuthorizationSequence
	if after < previous.Sequence {
		after = previous.Sequence
	}
	endpoint := c.endpointFor("/pull")
	query := endpoint.Query()
	query.Set("after", strconv.FormatUint(after, 10))
	query.Set("scope", "authorizations")
	endpoint.RawQuery = query.Encode()
	var pull Pull
	if err := c.request(ctx, "GET", endpoint, nil, &pull); err != nil {
		return Pull{}, err
	}
	if pull.Sequence > 9007199254740991 {
		return Pull{}, errors.New("invalid authorization checkpoint")
	}
	verified, err := verifier.VerifyAuthorizationRefresh(ctx, pull, previous)
	if err != nil {
		return Pull{}, err
	}
	if err = c.config.Engine.AcceptAuthorizationRefreshAtEpoch(verified, c.config.Now(), c.epoch); err != nil {
		return Pull{}, err
	}
	return pull, nil
}
