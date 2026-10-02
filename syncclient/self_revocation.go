package syncclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

var ErrSelfRevocationExpired = errors.New("original self-revocation challenge expired; do not create a replacement implicitly")

type SelfRevocationStatus struct {
	State     string `json:"state"`
	Sequence  uint64 `json:"sequence,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// 只可由系统认证后的原生层密封；包含120秒交易所需的原随机session，不是Dart结果。
type selfRevocationWire struct {
	Version      int                            `json:"version"`
	SessionEpoch uint64                         `json:"sessionEpoch"`
	BaseSequence uint64                         `json:"baseSequence"`
	PreparedAt   int64                          `json:"preparedAt"`
	SessionToken string                         `json:"sessionToken"`
	Signed       cryptox.SignedDeviceRevocation `json:"signed"`
}

// SelfRevocationTransaction 是原生持钥事务；禁止将 ProtectedBytes 返回界面或日志。
type SelfRevocationTransaction struct {
	client *Client
	wire   selfRevocationWire
}

func (c *Client) PrepareSelfRevocation(ctx context.Context, id string, key ed25519.PrivateKey) (*SelfRevocationTransaction, error) {
	if !enrollmentID.MatchString(id) || len(id) > 64 {
		return nil, errors.New("self-revocation request id invalid")
	}
	verifier, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), verifier.trust.DeviceSigningPublicKey) {
		return nil, errors.New("self-revocation requires exact pinned signing key")
	}
	if c.config.Engine.State().Paused {
		return nil, ErrPaused
	}
	var challenge cryptox.DeviceRevocation
	if err := c.request(ctx, "POST", c.endpointFor("/device-revocations"), map[string]string{"subjectDeviceId": c.config.DeviceID, "idempotencyKey": id}, &challenge); err != nil {
		return nil, err
	}
	now := c.config.Now()
	wire := selfRevocationWire{Version: 1, SessionEpoch: c.epoch, BaseSequence: c.config.Engine.State().Cloud.Sequence, PreparedAt: now.Unix(), SessionToken: c.config.Token, Signed: cryptox.SignedDeviceRevocation{Revocation: challenge}}
	transaction := &SelfRevocationTransaction{client: c, wire: wire}
	if err := transaction.validate(false); err != nil {
		return nil, err
	}
	if challenge.IdempotencyKey != id {
		return nil, errors.New("self-revocation id changed")
	}
	if err := transaction.currentAuthorities(); err != nil {
		return nil, err
	}
	signed, err := cryptox.SignDeviceRevocation(challenge, key)
	if err != nil {
		return nil, err
	}
	transaction.wire.Signed = signed
	return transaction, nil
}

// RestoreSelfRevocation 只接受原生AES认证解包的交易，不做boot换session或重新签名。
func (c *Client) RestoreSelfRevocation(protected []byte) (*SelfRevocationTransaction, error) {
	if len(protected) == 0 || len(protected) > 65536 {
		return nil, errors.New("self-revocation protected transaction size invalid")
	}
	var wire selfRevocationWire
	decoder := json.NewDecoder(bytes.NewReader(protected))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return nil, errors.New("self-revocation protected transaction invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("self-revocation trailing transaction content")
	}
	restored := *c
	restored.config = c.config
	restored.config.Token = wire.SessionToken
	transaction := &SelfRevocationTransaction{client: &restored, wire: wire}
	if err := transaction.validate(true); err != nil {
		return nil, err
	}
	return transaction, nil
}
func (t *SelfRevocationTransaction) validate(signed bool) error {
	c, r := t.client, t.wire.Signed.Revocation
	verifier, ok := c.config.Verifier.(*PinnedVerifier)
	if !ok || t.wire.Version != 1 || t.wire.SessionEpoch != c.epoch || c.config.Engine.State().SessionEpoch != c.epoch || c.config.Engine.State().AccountClosed || t.wire.BaseSequence > 9007199254740991 || t.wire.PreparedAt <= 0 {
		return errors.New("self-revocation local account epoch invalid")
	}
	if r.AccountID != c.config.AccountID || r.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || r.DeviceID != c.config.DeviceID || r.SubjectDeviceID != c.config.DeviceID || r.SubjectSigningPublicKey != cryptox.EncodeBase64(verifier.trust.DeviceSigningPublicKey) || r.SubjectReceivingPublicKey != verifier.receivingPublicKey || !enrollmentID.MatchString(r.IdempotencyKey) || len(r.IdempotencyKey) > 64 {
		return errors.New("self-revocation exact device/account/public keys mismatch")
	}
	if t.wire.SessionToken != "" {
		if _, err := cryptox.DecodeBase64(t.wire.SessionToken, 32, 32); err != nil {
			return errors.New("self-revocation original random session invalid")
		}
		hash := sha256.Sum256([]byte(t.wire.SessionToken))
		if r.SessionHash != hex.EncodeToString(hash[:]) {
			return errors.New("self-revocation original session binding mismatch")
		}
	} else {
		expiry, err := strconv.ParseInt(r.ExpiresAt, 10, 64)
		if err != nil || expiry > c.config.Now().Unix() {
			return errors.New("live self-revocation requires original random session")
		}
	}
	if _, err := r.SigningBytes(); err != nil {
		return err
	}
	expiry, err := strconv.ParseInt(r.ExpiresAt, 10, 64)
	if err != nil || expiry <= t.wire.PreparedAt || expiry > t.wire.PreparedAt+125 || c.config.Now().Unix() < t.wire.PreparedAt-5 {
		return errors.New("self-revocation challenge deadline binding invalid")
	}
	if signed {
		return cryptox.VerifyDeviceRevocation(t.wire.Signed, verifier.trust.DeviceSigningPublicKey)
	}
	return nil
}
func (t *SelfRevocationTransaction) currentAuthorities() error {
	snapshot := t.client.config.Engine.State().Cloud
	r := t.wire.Signed.Revocation
	if len(snapshot.Environments) == 0 || len(r.Authorities) != len(snapshot.Environments) {
		return localstate.ErrUnauthorized
	}
	for _, authority := range r.Authorities {
		env, ok := snapshot.Environments[authority.EnvironmentID]
		if !ok || env.Role != localstate.Admin || authority.KeyVersion != strconv.FormatUint(env.KeyVersion, 10) || authority.GrantGeneration != strconv.FormatUint(env.GrantGeneration, 10) || env.ExpiresAt != nil && !t.client.config.Now().Before(*env.ExpiresAt) {
			return localstate.ErrUnauthorized
		}
	}
	return nil
}
func (t *SelfRevocationTransaction) ProtectedBytes() ([]byte, error) {
	if err := t.validate(true); err != nil {
		return nil, err
	}
	return json.Marshal(t.wire)
}
func (t *SelfRevocationTransaction) ID() string { return t.wire.Signed.Revocation.IdempotencyKey }
func (t *SelfRevocationTransaction) ExpiresAt() int64 {
	n, _ := strconv.ParseInt(t.wire.Signed.Revocation.ExpiresAt, 10, 64)
	return n
}
func (t *SelfRevocationTransaction) Query(ctx context.Context) (SelfRevocationStatus, error) {
	if err := t.validate(true); err != nil {
		return SelfRevocationStatus{}, err
	}
	if t.ExpiresAt() <= t.client.config.Now().Unix() {
		return SelfRevocationStatus{}, ErrSelfRevocationExpired
	}
	var status SelfRevocationStatus
	if err := t.client.request(ctx, "GET", t.client.endpointFor("/device-revocations/"+t.ID()), nil, &status); err != nil {
		return status, err
	}
	switch status.State {
	case "pending":
		if status.Sequence != 0 || status.ExpiresAt != t.wire.Signed.Revocation.ExpiresAt {
			return SelfRevocationStatus{}, errors.New("self-revocation pending receipt binding mismatch")
		}
	case "complete":
		if status.Sequence <= t.wire.BaseSequence || status.Sequence > 9007199254740991 || status.ExpiresAt != "" {
			return SelfRevocationStatus{}, errors.New("self-revocation completion receipt invalid")
		}
	case "unknown":
		if status.Sequence != 0 || status.ExpiresAt != "" {
			return SelfRevocationStatus{}, errors.New("self-revocation unknown receipt invalid")
		}
	default:
		return SelfRevocationStatus{}, errors.New("self-revocation receipt state invalid")
	}
	return status, nil
}
func (t *SelfRevocationTransaction) Submit(ctx context.Context) (Acceptance, error) {
	if err := t.validate(true); err != nil {
		return Acceptance{}, err
	}
	if t.ExpiresAt() <= t.client.config.Now().Unix() {
		return Acceptance{}, ErrSelfRevocationExpired
	}
	if err := t.currentAuthorities(); err != nil {
		return Acceptance{}, err
	}
	var accepted Acceptance
	if err := t.client.request(ctx, "POST", t.client.endpointFor("/device-revocations/complete"), t.wire.Signed, &accepted); err != nil {
		return accepted, err
	}
	if accepted.Sequence <= t.wire.BaseSequence || accepted.Sequence > 9007199254740991 {
		return Acceptance{}, errors.New("self-revocation acceptance sequence invalid")
	}
	return accepted, nil
}

// RefreshOriginalAuthorities 沿原交易session拉取当前权限，不能替换token/签包。
func (t *SelfRevocationTransaction) RefreshOriginalAuthorities(ctx context.Context) error {
	_, err := t.client.Pull(ctx)
	return err
}

// ExpiredStatusWith 使用新boot会话只能查询原id；不能把原交易绑定改成新session。
func (c *Client) SelfRevocationStatus(ctx context.Context, id string) (SelfRevocationStatus, error) {
	if !enrollmentID.MatchString(id) || len(id) > 64 {
		return SelfRevocationStatus{}, errors.New("self-revocation status id invalid")
	}
	var status SelfRevocationStatus
	if err := c.request(ctx, "GET", c.endpointFor("/device-revocations/"+id), nil, &status); err != nil {
		return status, err
	}
	if status.State != "pending" && status.State != "unknown" && status.State != "complete" {
		return status, errors.New("self-revocation status invalid")
	}
	return status, nil
}

// QueryThrough只查询原id；不把原签名挑战改绑新boot token。
func (t *SelfRevocationTransaction) QueryThrough(ctx context.Context, current *Client) (SelfRevocationStatus, error) {
	if err := t.validate(true); err != nil {
		return SelfRevocationStatus{}, err
	}
	verifier, ok := current.config.Verifier.(*PinnedVerifier)
	r := t.wire.Signed.Revocation
	if !ok || current.config.AccountID != r.AccountID || strconv.FormatUint(current.config.AccountGeneration, 10) != r.AccountGeneration || current.config.DeviceID != r.DeviceID || cryptox.EncodeBase64(verifier.trust.DeviceSigningPublicKey) != r.SubjectSigningPublicKey || verifier.receivingPublicKey != r.SubjectReceivingPublicKey {
		return SelfRevocationStatus{}, errors.New("self-revocation status query identity mismatch")
	}
	status, err := current.SelfRevocationStatus(ctx, t.ID())
	if err != nil {
		return status, err
	}
	switch status.State {
	case "pending":
		if status.Sequence != 0 || status.ExpiresAt != r.ExpiresAt {
			return SelfRevocationStatus{}, errors.New("self-revocation pending receipt mismatch")
		}
	case "unknown":
		if status.Sequence != 0 || status.ExpiresAt != "" {
			return SelfRevocationStatus{}, errors.New("self-revocation unknown receipt mismatch")
		}
	case "complete":
		if status.Sequence <= t.wire.BaseSequence || status.Sequence > 9007199254740991 || status.ExpiresAt != "" {
			return SelfRevocationStatus{}, errors.New("self-revocation complete receipt invalid")
		}
	}
	return status, nil
}

// 到期清原bearer，只保留签包和状态查询证据；后续禁止原session任何HTTP请求。
func (t *SelfRevocationTransaction) DiscardExpiredToken() {
	if t.ExpiresAt() <= t.client.config.Now().Unix() {
		t.wire.SessionToken = ""
		t.client.config.Token = ""
	}
}
