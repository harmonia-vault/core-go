package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
	"io"
	"net/url"
)

func (c *Client) addEvidenceCapability(q url.Values) {
	q.Set("capability", cryptox.RecoveryDAGCapability)
}
func strictJSONBytes(data []byte, out any) error {
	if e := cryptox.ValidateStrictJSON(data, cryptox.MaxIssuerProofV2Bytes); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var x any
	if e := d.Decode(&x); e != io.EOF {
		return cryptox.ErrInvalidWire
	}
	return nil
}
func (v *PinnedVerifier) VerifyPull(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if e := v.ValidateStoredIssuerEvidence(previous); e != nil {
		return localstate.CloudSnapshot{}, e
	}
	candidate, evidence, e := v.withIssuerDAGEvidence(pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out, e := candidate.verifyPullValues(ctx, pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out.IssuerEvidence = bytes.Clone(evidence)
	if len(evidence) > 0 {
		if e = candidate.initializeCachedSources(&out, evidence); e != nil {
			return localstate.CloudSnapshot{}, e
		}
	}
	return out, nil
}
func (v *PinnedVerifier) VerifyAuthorizationRefresh(ctx context.Context, pull Pull, previous localstate.CloudSnapshot) (localstate.CloudSnapshot, error) {
	if e := v.ValidateStoredIssuerEvidence(previous); e != nil {
		return localstate.CloudSnapshot{}, e
	}
	candidate, evidence, e := v.withIssuerDAGEvidence(pull, previous)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out, e := candidate.verifyAuthorizationValues(ctx, pull, previous, evidence)
	if e != nil {
		return localstate.CloudSnapshot{}, e
	}
	out.IssuerEvidence = bytes.Clone(evidence)
	if len(evidence) > 0 {
		if e = candidate.ValidateStoredIssuerEvidence(out); e != nil {
			return localstate.CloudSnapshot{}, e
		}
	}
	return out, nil
}

func (v *PinnedVerifier) ValidateStoredIssuerEvidence(previous localstate.CloudSnapshot) error {
	if v.initialDAGEvidence == nil || v.evidenceRoot == nil {
		return cryptox.ErrInvalidWire
	}
	return v.validateStoredDAGEvidence(previous)
}
func issuerCacheRoleRank(role localstate.Role) int {
	switch role {
	case localstate.ReadOnly:
		return 1
	case localstate.ReadWrite:
		return 2
	case localstate.Admin:
		return 3
	default:
		return 0
	}
}
