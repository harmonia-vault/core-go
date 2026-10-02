package syncclient

import (
	"context"
	"errors"
	"regexp"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

type EnvironmentChangeStatus struct {
	State    string `json:"state"`
	Sequence uint64 `json:"sequence,omitempty"`
}

func (c *Client) EnvironmentStatus(ctx context.Context, id string) (EnvironmentChangeStatus, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(id) {
		return EnvironmentChangeStatus{}, errors.New("invalid environment request id")
	}
	var status EnvironmentChangeStatus
	if err := c.request(ctx, "GET", c.endpointFor("/environment-changes/"+id), nil, &status); err != nil {
		return status, err
	}
	if status.State != "complete" && status.State != "unknown" || status.State == "complete" && (status.Sequence == 0 || status.Sequence > 9007199254740991) || status.State == "unknown" && status.Sequence != 0 {
		return EnvironmentChangeStatus{}, errors.New("invalid environment status")
	}
	return status, nil
}
func (c *Client) ConfirmEnvironmentChange(ctx context.Context, signed cryptox.SignedEnvironmentChange, accepted Acceptance) (SubmitResult, error) {
	result := SubmitResult{Accepted: accepted}
	if err := c.validateEnvironmentChange(signed); err != nil {
		return result, err
	}
	if accepted.Sequence == 0 || accepted.Sequence > 9007199254740991 {
		return result, errors.New("invalid environment acceptance")
	}
	if _, err := c.Pull(ctx); err != nil {
		return result, errors.Join(ErrAcceptedNotApplied, err)
	}
	if err := VerifyEnvironmentChangeCheckpoint(c.config.Engine.State().Cloud, signed, accepted.Sequence); err != nil {
		return result, err
	}
	result.Applied = true
	return result, nil
}
func (c *Client) SubmitEnvironmentChange(ctx context.Context, signed cryptox.SignedEnvironmentChange) (SubmitResult, error) {
	if err := c.validateEnvironmentChange(signed); err != nil {
		return SubmitResult{}, err
	}
	var accepted Acceptance
	if err := c.request(ctx, "POST", c.endpointFor("/environment-changes"), signed, &accepted); err != nil {
		return SubmitResult{}, err
	}
	return c.ConfirmEnvironmentChange(ctx, signed, accepted)
}

func (c *Client) validateEnvironmentChange(signed cryptox.SignedEnvironmentChange) error {
	change := signed.Change
	if change.AccountID != c.config.AccountID || change.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || change.DeviceID != c.config.DeviceID {
		return errors.New("environment operation not bound to current device")
	}
	if c.config.Engine.State().Paused {
		return ErrPaused
	}
	if verifier, ok := c.config.Verifier.(*PinnedVerifier); ok {
		return cryptox.VerifyEnvironmentChange(signed, verifier.trust.DeviceSigningPublicKey)
	}
	_, err := change.SigningBytes()
	return err
}
