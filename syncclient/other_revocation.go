package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

// otherRevocationRecord 只供原生加密状态保存，短时原 bearer 不进入界面或日志。
type otherRevocationRecord struct {
	Wire    selfRevocationWire `json:"wire"`
	Control ManagementControl  `json:"control"`
}
type OtherRevocationTransaction struct {
	client *Client
	record otherRevocationRecord
}

func DeviceRevocationContentHash(s cryptox.SignedDeviceRevocation) (string, error) {
	wire, e := s.Revocation.SigningBytes()
	if e != nil {
		return "", e
	}
	if _, e = cryptox.DecodeBase64(s.Signature, 64, 64); e != nil {
		return "", e
	}
	sum := sha256.Sum256([]byte(cryptox.EncodeBase64(wire) + "." + s.Signature))
	return hex.EncodeToString(sum[:]), nil
}
func (c *Client) DeviceRevocationReceipt(ctx context.Context, id string) (GrantStatus, error) {
	if !enrollmentID.MatchString(id) || len(id) > 64 {
		return GrantStatus{}, cryptox.ErrInvalidWire
	}
	target := c.endpointFor("/device-revocation-status")
	query := target.Query()
	query.Set("idempotencyKey", id)
	target.RawQuery = query.Encode()
	var status GrantStatus
	if e := c.request(ctx, "GET", target, nil, &status); e != nil {
		return status, e
	}
	if status.IdempotencyKey != id || !status.Accepted && (status.Sequence != 0 || status.ContentHash != "") || status.Accepted && (status.Sequence == 0 || status.Sequence > 9007199254740991 || !lowerHash(status.ContentHash)) {
		return GrantStatus{}, cryptox.ErrInvalidWire
	}
	return status, nil
}
func (c *Client) PrepareOtherRevocation(ctx context.Context, id, subject, environment string, key ed25519.PrivateKey) (*OtherRevocationTransaction, error) {
	if c.config.Engine.State().Paused {
		return nil, ErrPaused
	}
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), v.trust.DeviceSigningPublicKey) || subject == c.config.DeviceID || !enrollmentID.MatchString(id) || len(id) > 64 {
		return nil, ErrWritePermission
	}
	receipt, e := c.DeviceRevocationReceipt(ctx, id)
	if e != nil {
		return nil, e
	}
	if receipt.Accepted {
		return nil, ErrGrantUpdateConflict
	}
	control, e := c.ManagementControl(ctx, environment)
	if e != nil {
		return nil, e
	}
	var challenge cryptox.DeviceRevocation
	if e = c.request(ctx, "POST", c.endpointFor("/device-revocations"), map[string]string{"subjectDeviceId": subject, "idempotencyKey": id}, &challenge); e != nil {
		return nil, e
	}
	t := &OtherRevocationTransaction{client: c, record: otherRevocationRecord{Wire: selfRevocationWire{Version: 1, SessionEpoch: c.epoch, BaseSequence: c.config.Engine.State().Cloud.Sequence, PreparedAt: c.config.Now().Unix(), SessionToken: c.config.Token, Signed: cryptox.SignedDeviceRevocation{Revocation: challenge}}, Control: control}}
	if challenge.IdempotencyKey != id || challenge.SubjectDeviceID != subject {
		return nil, cryptox.ErrInvalidWire
	}
	if e = t.validate(false); e != nil {
		return nil, e
	}
	if e = t.currentAuthorities(); e != nil {
		return nil, e
	}
	t.record.Wire.Signed, e = cryptox.SignDeviceRevocation(challenge, key)
	if e != nil {
		return nil, e
	}
	return t, nil
}
func (c *Client) RestoreOtherRevocation(data []byte) (*OtherRevocationTransaction, error) {
	if len(data) == 0 || len(data) > 2<<20 || cryptox.ValidateStrictJSON(data, 2<<20) != nil {
		return nil, cryptox.ErrInvalidWire
	}
	var saved otherRevocationRecord
	if e := strictTransaction(data, &saved); e != nil {
		return nil, e
	}
	old := *c
	old.config = c.config
	old.config.Token = saved.Wire.SessionToken
	t := &OtherRevocationTransaction{client: &old, record: saved}
	if e := t.validate(true); e != nil {
		return nil, e
	}
	return t, nil
}
func (t *OtherRevocationTransaction) validate(signed bool) error {
	c, w := t.client, t.record.Wire
	r := w.Signed.Revocation
	v, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || w.Version != 1 || w.SessionEpoch != c.epoch || c.config.Engine.State().SessionEpoch != c.epoch || c.config.Engine.State().AccountClosed || w.BaseSequence > 9007199254740991 || w.PreparedAt <= 0 || r.AccountID != c.config.AccountID || r.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || r.DeviceID != c.config.DeviceID || r.SubjectDeviceID == c.config.DeviceID || !enrollmentID.MatchString(r.IdempotencyKey) || len(r.IdempotencyKey) > 64 {
		return cryptox.ErrInvalidWire
	}
	_, _, e := c.verifyManagementControl(t.record.Control, true)
	if e != nil {
		return e
	}
	found := false
	for _, subject := range t.record.Control.Subjects {
		if subject.DeviceID == r.SubjectDeviceID && subject.SigningPublicKey == r.SubjectSigningPublicKey && subject.ReceivingPublicKey == r.SubjectReceivingPublicKey {
			found = true
		}
	}
	if !found {
		return cryptox.ErrInvalidWire
	}
	if _, e = r.SigningBytes(); e != nil {
		return e
	}
	expiry, e := strconv.ParseInt(r.ExpiresAt, 10, 64)
	if e != nil || expiry <= w.PreparedAt || expiry > w.PreparedAt+125 || c.config.Now().Unix() < w.PreparedAt-5 {
		return cryptox.ErrInvalidWire
	}
	if w.SessionToken != "" {
		if _, e = cryptox.DecodeBase64(w.SessionToken, 32, 32); e != nil {
			return e
		}
		sum := sha256.Sum256([]byte(w.SessionToken))
		if r.SessionHash != hex.EncodeToString(sum[:]) {
			return cryptox.ErrInvalidWire
		}
	} else if expiry > c.config.Now().Unix() {
		return cryptox.ErrInvalidWire
	}
	if signed {
		return cryptox.VerifyDeviceRevocation(w.Signed, v.trust.DeviceSigningPublicKey)
	}
	return nil
}
func (t *OtherRevocationTransaction) currentAuthorities() error {
	state := t.client.config.Engine.State()
	r := t.record.Wire.Signed.Revocation
	if state.Paused {
		return ErrPaused
	}
	if len(state.Cloud.Environments) == 0 || len(r.Authorities) != len(state.Cloud.Environments) {
		return localstate.ErrUnauthorized
	}
	seen := map[string]bool{}
	for _, a := range r.Authorities {
		env, ok := state.Cloud.Environments[a.EnvironmentID]
		if !ok || seen[a.EnvironmentID] || env.Role != localstate.Admin || a.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || a.GrantGeneration != strconv.FormatUint(env.GrantGeneration, 10) || env.ExpiresAt != nil && !t.client.config.Now().Before(*env.ExpiresAt) {
			return localstate.ErrUnauthorized
		}
		seen[a.EnvironmentID] = true
	}
	return nil
}
func (t *OtherRevocationTransaction) ID() string {
	return t.record.Wire.Signed.Revocation.IdempotencyKey
}
func (t *OtherRevocationTransaction) SubjectDeviceID() string {
	return t.record.Wire.Signed.Revocation.SubjectDeviceID
}
func (t *OtherRevocationTransaction) ExpiresAt() int64 {
	n, _ := strconv.ParseInt(t.record.Wire.Signed.Revocation.ExpiresAt, 10, 64)
	return n
}
func (t *OtherRevocationTransaction) ContentHash() (string, error) {
	return DeviceRevocationContentHash(t.record.Wire.Signed)
}
func (t *OtherRevocationTransaction) ProtectedBytes() ([]byte, error) {
	if e := t.validate(true); e != nil {
		return nil, e
	}
	data, e := json.Marshal(t.record)
	if len(data) > 2<<20 {
		return nil, cryptox.ErrInvalidWire
	}
	return data, e
}
func (t *OtherRevocationTransaction) DiscardExpiredToken() {
	if t.ExpiresAt() <= t.client.config.Now().Unix() {
		t.record.Wire.SessionToken = ""
		t.client.config.Token = ""
	}
}
func (t *OtherRevocationTransaction) StatusThrough(ctx context.Context, current *Client) (GrantStatus, error) {
	if e := t.validate(true); e != nil {
		return GrantStatus{}, e
	}
	if current.config.AccountID != t.client.config.AccountID || current.config.AccountGeneration != t.client.config.AccountGeneration || current.config.DeviceID != t.client.config.DeviceID || current.epoch != t.client.epoch {
		return GrantStatus{}, cryptox.ErrInvalidWire
	}
	status, e := current.DeviceRevocationReceipt(ctx, t.ID())
	if e != nil {
		return status, e
	}
	if status.Accepted {
		hash, e := t.ContentHash()
		if e != nil || status.ContentHash != hash || status.Sequence <= t.record.Wire.BaseSequence {
			return GrantStatus{}, ErrGrantUpdateConflict
		}
	}
	return status, nil
}
func (t *OtherRevocationTransaction) Submit(ctx context.Context) (Acceptance, error) {
	return t.submit(ctx, nil)
}

// SubmitWithBarrier 与改权相同，只在原短时session的检查通过后调用写入屏障。
func (t *OtherRevocationTransaction) SubmitWithBarrier(ctx context.Context, beforePost func() error) (Acceptance, error) {
	if beforePost == nil {
		return Acceptance{}, cryptox.ErrInvalidWire
	}
	return t.submit(ctx, beforePost)
}
func (t *OtherRevocationTransaction) submit(ctx context.Context, beforePost func() error) (Acceptance, error) {
	if e := t.validate(true); e != nil {
		return Acceptance{}, e
	}
	if t.ExpiresAt() <= t.client.config.Now().Unix() {
		return Acceptance{}, ErrSelfRevocationExpired
	}
	if e := t.currentAuthorities(); e != nil {
		return Acceptance{}, e
	}
	if _, e := t.client.Pull(ctx); e != nil {
		return Acceptance{}, e
	}
	if e := t.currentAuthorities(); e != nil {
		return Acceptance{}, e
	}
	if beforePost != nil {
		if e := beforePost(); e != nil {
			return Acceptance{}, e
		}
	}
	var accepted Acceptance
	if e := t.client.request(ctx, "POST", t.client.endpointFor("/device-revocations/complete"), t.record.Wire.Signed, &accepted); e != nil {
		return accepted, e
	}
	if accepted.Sequence <= t.record.Wire.BaseSequence || accepted.Sequence > 9007199254740991 {
		return Acceptance{}, cryptox.ErrInvalidWire
	}
	return accepted, nil
}
func (t *OtherRevocationTransaction) ConfirmThrough(ctx context.Context, current *Client, accepted Acceptance) (SubmitResult, error) {
	out := SubmitResult{Accepted: accepted}
	status, e := t.StatusThrough(ctx, current)
	if e != nil {
		return out, e
	}
	if !status.Accepted || status.Sequence != accepted.Sequence {
		return out, ErrAcceptedNotApplied
	}
	if _, e = current.Pull(ctx); e != nil {
		return out, errors.Join(ErrAcceptedNotApplied, e)
	}
	if current.config.Engine.State().Paused || current.config.Engine.State().Cloud.Sequence < accepted.Sequence {
		return out, ErrAcceptedNotApplied
	}
	out.Applied = true
	return out, nil
}
func (t *OtherRevocationTransaction) ControlCheckpoint() ManagementControl {
	return cloneManagementControl(t.record.Control)
}
