// Package syncclient 提供 HTTPS、逐次请求身份绑定和提交后同流拉取。
// 验签/授权/解密由必须注入的 Verifier 完成；没有默认信任或配对旁路。
package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localstate"
)

var (
	ErrPaused             = errors.New("ordinary sync is paused")
	ErrAcceptedNotApplied = errors.New("server accepted the mutation but verified pull failed; query/pull before retrying, and keep the same idempotency key")
)

type Mutation = cryptox.Mutation
type Grant = cryptox.Grant
type SignedMutation struct {
	Mutation  Mutation `json:"mutation"`
	Signature string   `json:"signature"`
}
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}
type Event struct {
	Sequence      uint64         `json:"sequence"`
	Mutation      SignedMutation `json:"mutation"`
	Authorization *SignedGrant   `json:"authorization,omitempty"`
}
type Pull struct {
	Full              bool                   `json:"-"`
	IssuerEvidence    *cryptox.IssuerProofV2 `json:"issuerEvidence,omitempty"`
	Scope             string                 `json:"scope,omitempty"`
	EnvironmentEvents []EnvironmentEvent     `json:"environmentEvents,omitempty"`
	AccountID         string                 `json:"accountId"`
	AccountGeneration string                 `json:"accountGeneration"`
	Sequence          uint64                 `json:"sequence"`
	Grants            []SignedGrant          `json:"grants"`
	Events            []Event                `json:"events"`
}
type Acceptance struct {
	Sequence uint64 `json:"sequence"`
	Replayed bool   `json:"replayed"`
}
type SubmitResult struct {
	Accepted Acceptance
	Applied  bool
}

// Verifier 必须检查可信管理公钥、账号/代际、签授权、变更签名、key version、
// grant generation、回放检查点并解密。验证失败不能返回部分可应用快照。
type Verifier interface {
	VerifyPull(context.Context, Pull, localstate.CloudSnapshot) (localstate.CloudSnapshot, error)
}
type Config struct {
	Endpoint          string
	HTTPClient        *http.Client
	AccountID         string
	AccountGeneration uint64
	DeviceID          string
	Token             string
	Verifier          Verifier
	Engine            *localstate.Engine
	Now               func() time.Time
}
type Client struct {
	endpoint *url.URL
	http     *http.Client
	config   Config
	epoch    uint64
}

func New(config Config) (*Client, error) { return newClient(config, true) }

// NewForBoot 只准备既有可信设备的无登录凭据持钥挑战；还不能读取或写入。
func NewForBoot(config Config) (*Client, error) {
	if config.Token != "" {
		return nil, errors.New("boot must not retain a login credential")
	}
	return newClient(config, false)
}
func newClient(config Config, requireToken bool) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, errors.New("invalid HTTPS endpoint")
	}
	if endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("endpoint must be HTTPS without credentials, query or fragment")
	}
	if config.Engine == nil || config.Verifier == nil {
		return nil, errors.New("trusted verifier and local engine are required")
	}
	_, enrollmentOnly := config.Verifier.(deniedEnrollmentVerifier)
	if config.Engine.State().AccountClosed && !enrollmentOnly {
		return nil, localstate.ErrLocalSession
	}
	if config.Engine.State().Synthetic {
		return nil, errors.New("synthetic fixture state cannot connect to a server")
	}
	idPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	if !idPattern.MatchString(config.AccountID) || !idPattern.MatchString(config.DeviceID) || config.AccountGeneration == 0 || (requireToken && config.Token == "") || strings.ContainsAny(config.Token, "\r\n") {
		return nil, errors.New("bound account, device and login session are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	client, err := secureHTTP(config.HTTPClient)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: endpoint, http: client, config: config, epoch: config.Engine.State().SessionEpoch}, nil
}
func (c *Client) endpointFor(suffix string) *url.URL {
	u := *c.endpoint
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/accounts/" + url.PathEscape(c.config.AccountID) + suffix
	u.RawPath = ""
	return &u
}
func (c *Client) request(ctx context.Context, method string, u *url.URL, body any, out any) error {
	if c.config.Engine.State().SessionEpoch != c.epoch {
		return localstate.ErrLocalSession
	}
	bootRoute := strings.HasSuffix(u.Path, "/boot-challenges") || strings.HasSuffix(u.Path, "/boot-sessions")
	if c.config.Token == "" && !bootRoute {
		return errors.New("device-bound session required")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return errors.New("could not build server request")
	}
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}
	req.Header.Set("X-Harmonia-Device-Id", c.config.DeviceID)
	req.Header.Set("X-Harmonia-Account-Generation", strconv.FormatUint(c.config.AccountGeneration, 10))
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("HTTPS request failed")
	}
	defer response.Body.Close()
	if c.config.Engine.State().SessionEpoch != c.epoch {
		return localstate.ErrLocalSession
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return c.rejection(response, bootRoute)
	}
	const maximum = 8 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return errors.New("could not read server response")
	}
	if len(data) > maximum {
		return errors.New("server response exceeds size limit")
	}
	if cryptox.ValidateStrictJSON(data, maximum) != nil {
		return errors.New("server response does not match protocol")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(out); err != nil {
		return errors.New("server response does not match protocol")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("server returned extra JSON content")
	}
	return nil
}

// Pull 持久化序号拉取；通知应仅唤醒它，不能把 WS 内容直接视为权威值。
func (c *Client) Pull(ctx context.Context) (Pull, error) {
	state := c.config.Engine.State()
	if state.Paused {
		return Pull{}, ErrPaused
	}
	return c.pullWithHistory(ctx, state.Cloud, state.Cloud.AuthorizationSequence > state.Cloud.Sequence)
}
func (c *Client) pull(ctx context.Context, previous localstate.CloudSnapshot) (Pull, error) {
	return c.pullWithHistory(ctx, previous, false)
}
func (c *Client) pullWithHistory(ctx context.Context, previous localstate.CloudSnapshot, full bool) (Pull, error) {
	u := c.endpointFor("/pull")
	q := u.Query()
	after := previous.Sequence
	if full {
		after = 0
	}
	q.Set("after", strconv.FormatUint(after, 10))
	c.addEvidenceCapability(q)
	u.RawQuery = q.Encode()
	var result Pull
	if err := c.request(ctx, http.MethodGet, u, nil, &result); err != nil {
		return Pull{}, err
	}
	if result.AccountID != c.config.AccountID || result.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || result.Sequence < previous.Sequence || result.Sequence > 9007199254740991 {
		return Pull{}, errors.New("pull account/generation/checkpoint mismatch")
	}
	result.Full = full || previous.Sequence == 0
	last := after
	for _, event := range result.Events {
		if event.Sequence <= last || event.Sequence > result.Sequence {
			return Pull{}, errors.New("unordered or replayed pull event")
		}
		last = event.Sequence
	}
	if c.config.Engine.State().Paused {
		return Pull{}, c.acceptLateAuthorizationProjection(ctx, result, previous)
	}
	verified, err := c.config.Verifier.VerifyPull(ctx, result, previous)
	if err != nil {
		if c.config.Engine.State().Paused {
			return Pull{}, c.acceptLateAuthorizationProjection(ctx, result, previous)
		}
		if errors.Is(err, ErrFullPullRequired) && !full {
			return c.pullWithHistory(ctx, previous, true)
		}
		return Pull{}, fmt.Errorf("pull verification failed: %w", err)
	}
	if verified.AccountID != result.AccountID || verified.AccountGeneration != c.config.AccountGeneration || verified.Sequence != result.Sequence {
		return Pull{}, errors.New("verifier returned an unbound checkpoint")
	}
	if err = c.config.Engine.AcceptDataSnapshotAtEpoch(verified, c.config.Now(), c.epoch); err != nil {
		if errors.Is(err, localstate.ErrDataPaused) {
			return Pull{}, c.acceptLateAuthorizationProjection(ctx, result, previous)
		}
		return Pull{}, err
	}
	return result, nil
}

// AcceptRevocationHint 为已认证通知后的授权刷新入口。暂停时只执行已知撤销/
// 过期的本地安全重算；普通值写入仍由 localstate 的暂停行为阻止。
func (c *Client) AcceptRevocationHint(ctx context.Context) (Pull, error) {
	return c.RefreshAuthorizations(ctx)
}

// Submit 不乐观更改本地权威状态；网络失败可离线读取，不能离线共享写。
// 接受后拉取失败时返回原序号，调用方须保留幂等键并查询状态。
func (c *Client) Submit(ctx context.Context, mutation SignedMutation) (SubmitResult, error) {
	m := mutation.Mutation
	if m.AccountID != c.config.AccountID || m.AccountGeneration != strconv.FormatUint(c.config.AccountGeneration, 10) || m.DeviceID != c.config.DeviceID || m.IdempotencyKey == "" || mutation.Signature == "" || (m.Operation != "put" && m.Operation != "delete") {
		return SubmitResult{}, errors.New("mutation identity or operation is not bound to this device")
	}
	var accepted Acceptance
	if err := c.request(ctx, http.MethodPost, c.endpointFor("/mutations"), mutation, &accepted); err != nil {
		return SubmitResult{}, err
	}
	if accepted.Sequence == 0 || accepted.Sequence > 9007199254740991 {
		return SubmitResult{}, errors.New("invalid mutation acceptance sequence")
	}
	result := SubmitResult{Accepted: accepted}
	if _, err := c.Pull(ctx); err != nil {
		return result, errors.Join(ErrAcceptedNotApplied, err)
	}
	if c.config.Engine.State().Cloud.Sequence < accepted.Sequence {
		return result, ErrAcceptedNotApplied
	}
	result.Applied = true
	return result, nil
}
