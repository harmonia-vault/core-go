// Package accountreset implements only the existing email-owned reset protocol.
// It never grants device trust, initializes a vault, or clears native storage.
package accountreset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/syncclient"
)

var (
	ErrInput         = errors.New("account reset input invalid")
	ErrResponse      = errors.New("account reset response invalid")
	ErrTransport     = errors.New("account reset HTTPS request failed")
	ErrUnknown       = errors.New("account reset result unknown; query the original proof")
	ErrQueryRequired = errors.New("query the original account reset before retrying")
	ErrClosed        = errors.New("account reset operation closed")
	ErrBusy          = errors.New("account reset operation busy")
)

const Confirmation = "DELETE_OLD_VAULT"
const maximumWire = 4096

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Config struct {
	Endpoint string
	// Trusted native configuration only; never accept a client or CA from a UI command.
	HTTPClient *http.Client
}
type Client struct {
	endpoint string
	http     *http.Client
}

type Proof struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	ChallengeID       string `json:"challengeId"`
	Token             string `json:"token"`
}

// Outcome contains public metadata only. Source distinguishes a status proof
// from the commit response. Neither source grants login or device trust.
type Outcome struct {
	State             string `json:"state"`
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	Source            string `json:"source"`
	Replayed          *bool  `json:"replayed,omitempty"`
}

func New(config Config) (*Client, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil || len(config.Endpoint) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(config.Endpoint, "\\\x00\r\n\t") {
		return nil, ErrInput
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path != "" && path.Clean(u.Path) != u.Path {
		return nil, ErrInput
	}
	h := &http.Client{Timeout: 20 * time.Second}
	if config.HTTPClient != nil {
		*h = *config.HTTPClient
	}
	transport := h.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	tr, ok := transport.(*http.Transport)
	if !ok {
		return nil, ErrInput
	}
	tr = tr.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion != 0 && tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		return nil, ErrInput
	}
	if tr.TLSClientConfig.MinVersion == 0 {
		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	h.Transport, h.Jar = tr, nil
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if h.Timeout <= 0 || h.Timeout > 30*time.Second {
		h.Timeout = 20 * time.Second
	}
	return &Client{endpoint: u.String(), http: h}, nil
}

func proofGeneration(p Proof) (uint64, error) {
	n, e := strconv.ParseUint(p.AccountGeneration, 10, 64)
	if e != nil || n == 0 || n == ^uint64(0) || strconv.FormatUint(n, 10) != p.AccountGeneration || !idPattern.MatchString(p.AccountID) || !idPattern.MatchString(p.ChallengeID) {
		return 0, ErrInput
	}
	token, e := cryptox.DecodeBase64(p.Token, 32, 32)
	clear(token)
	if e != nil {
		return 0, ErrInput
	}
	return n, nil
}

// ParseProof accepts the exact four-field JSON from the requested email.
// A proof is a bearer secret: never log it, put it in a URL, or persist it in Dart.
func ParseProof(data []byte) (Proof, error) {
	var p Proof
	if exactJSON(data, &p, "accountId", "accountGeneration", "challengeId", "token") != nil {
		return Proof{}, ErrInput
	}
	if _, e := proofGeneration(p); e != nil {
		return Proof{}, e
	}
	return p, nil
}

func (c *Client) RequestProof(ctx context.Context, email string) error {
	if email == "" || len(email) > 320 || !utf8.ValidString(email) || strings.ContainsAny(email, "\x00\r\n") {
		return ErrInput
	}
	body, _ := json.Marshal(struct {
		Email string `json:"email"`
	}{email})
	defer clear(body)
	data, e := c.post(ctx, "/v1/account-reset/request", body)
	if e != nil {
		return e
	}
	defer clear(data)
	var out struct {
		Accepted *bool `json:"accepted"`
	}
	if exactJSON(data, &out, "accepted") != nil || out.Accepted == nil || !*out.Accepted {
		return ErrResponse
	}
	return nil
}

func proofBody(p Proof) []byte {
	b, _ := json.Marshal(struct {
		Generation string `json:"accountGeneration"`
		Challenge  string `json:"challengeId"`
		Token      string `json:"token"`
	}{p.AccountGeneration, p.ChallengeID, p.Token})
	return b
}

// Query permits a new phone to resolve the original proof without old device
// keys or a password. It never submits a reset, including when state is pending.
func (c *Client) Query(ctx context.Context, p Proof) (Outcome, error) {
	if _, e := proofGeneration(p); e != nil {
		return Outcome{}, e
	}
	body := proofBody(p)
	defer clear(body)
	data, e := c.post(ctx, "/v1/accounts/"+p.AccountID+"/account-reset/status", body)
	if e != nil {
		return Outcome{}, e
	}
	defer clear(data)
	return statusResponse(p, data)
}

// Attempt freezes the endpoint, original proof and exact commit payload in RAM.
// No method can replace the password/proof after construction. After uncertainty,
// Submit is blocked until Query confirms pending. Close cancels in-flight work.
// Native integration must first prove local old-slot cleanup, independently of UI.
type Attempt struct {
	mu              sync.Mutex
	client          *Client
	proof           Proof
	commit          []byte
	query           []byte
	out             Outcome
	running, closed bool
	cancel          context.CancelFunc
}

// NewAttempt consumes and clears password on all exits. Password-equivalent bytes
// remain only in the private frozen payload until completion or Close.
func (c *Client) NewAttempt(p Proof, password []byte, confirmation string) (*Attempt, error) {
	defer clear(password)
	if _, e := proofGeneration(p); e != nil {
		return nil, e
	}
	if confirmation != Confirmation || len(password) == 0 || len(password) > 16384 || !utf8.Valid(password) {
		return nil, ErrInput
	}
	digest := sha256.Sum256(password)
	defer clear(digest[:])
	encoded := make([]byte, 64)
	hex.Encode(encoded, digest[:])
	defer clear(encoded)
	payload, _ := json.Marshal(struct {
		Generation   string `json:"accountGeneration"`
		Challenge    string `json:"challengeId"`
		Token        string `json:"token"`
		Credential   string `json:"newCredential"`
		Confirmation string `json:"confirmation"`
	}{p.AccountGeneration, p.ChallengeID, p.Token, string(encoded), Confirmation})
	return &Attempt{client: c, proof: p, commit: payload, query: proofBody(p), out: Outcome{State: "ready", AccountID: p.AccountID, AccountGeneration: p.AccountGeneration, Source: "local"}}, nil
}

func (a *Attempt) Submit(ctx context.Context) (Outcome, error) { return a.run(ctx, true) }
func (a *Attempt) Query(ctx context.Context) (Outcome, error)  { return a.run(ctx, false) }
func (a *Attempt) Close() {
	a.mu.Lock()
	a.closed = true
	cancel := a.cancel
	clear(a.commit)
	clear(a.query)
	a.commit = nil
	a.query = nil
	a.proof = Proof{}
	a.out = Outcome{}
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func cloneOutcome(o Outcome) Outcome {
	if o.Replayed != nil {
		v := *o.Replayed
		o.Replayed = &v
	}
	return o
}
func (a *Attempt) run(ctx context.Context, submit bool) (Outcome, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return Outcome{}, ErrClosed
	}
	if a.running {
		a.mu.Unlock()
		return Outcome{}, ErrBusy
	}
	if ctx.Err() != nil {
		a.mu.Unlock()
		return Outcome{}, ctx.Err()
	}
	if a.out.State == "complete" {
		out := cloneOutcome(a.out)
		a.mu.Unlock()
		return out, nil
	}
	if submit && a.out.State == "unknown" {
		a.mu.Unlock()
		return Outcome{}, ErrQueryRequired
	}
	p := a.proof
	body := append([]byte(nil), a.query...)
	suffix := "status"
	if submit {
		clear(body)
		body = append([]byte(nil), a.commit...)
		suffix = "complete"
		a.out.State = "unknown"
		a.out.Source = "local"
	}
	operation, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.running = true
	a.mu.Unlock()
	defer cancel()
	defer clear(body)
	data, e := a.client.post(operation, "/v1/accounts/"+p.AccountID+"/account-reset/"+suffix, body)
	defer clear(data)
	var out Outcome
	if e == nil {
		if submit {
			out, e = completeResponse(p, data)
		} else {
			out, e = statusResponse(p, data)
		}
	}
	// A caller cancellation retires delivery even if transport completion races
	// cancellation. A submitted request remains uncertain until the original query.
	if e == nil && operation.Err() != nil {
		e = ErrTransport
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	a.cancel = nil
	if a.closed {
		return Outcome{}, ErrClosed
	}
	if e != nil {
		if submit {
			return cloneOutcome(a.out), errors.Join(ErrUnknown, e)
		}
		return Outcome{}, e
	}
	a.out = cloneOutcome(out)
	if out.State == "complete" {
		clear(a.commit)
		clear(a.query)
		a.commit = nil
		a.query = nil
		a.proof = Proof{}
	}
	return out, nil
}

func statusResponse(p Proof, data []byte) (Outcome, error) {
	var wire struct {
		State      string `json:"state"`
		AccountID  string `json:"accountId"`
		Generation string `json:"accountGeneration"`
	}
	if exactJSON(data, &wire, "state", "accountId", "accountGeneration") != nil {
		return Outcome{}, ErrResponse
	}
	n, e := proofGeneration(p)
	if e != nil {
		return Outcome{}, e
	}
	want := p.AccountGeneration
	if wire.State == "complete" {
		want = strconv.FormatUint(n+1, 10)
	} else if wire.State != "pending" {
		return Outcome{}, ErrResponse
	}
	if wire.AccountID != p.AccountID || wire.Generation != want {
		return Outcome{}, ErrResponse
	}
	return Outcome{State: wire.State, AccountID: wire.AccountID, AccountGeneration: wire.Generation, Source: "status"}, nil
}
func completeResponse(p Proof, data []byte) (Outcome, error) {
	var wire struct {
		AccountID  string `json:"accountId"`
		Generation string `json:"accountGeneration"`
		Replayed   *bool  `json:"replayed"`
	}
	if exactJSON(data, &wire, "accountId", "accountGeneration", "replayed") != nil {
		return Outcome{}, ErrResponse
	}
	n, e := proofGeneration(p)
	if e != nil {
		return Outcome{}, e
	}
	if wire.AccountID != p.AccountID || wire.Generation != strconv.FormatUint(n+1, 10) || wire.Replayed == nil {
		return Outcome{}, ErrResponse
	}
	return Outcome{State: "complete", AccountID: wire.AccountID, AccountGeneration: wire.Generation, Source: "commit", Replayed: wire.Replayed}, nil
}

func exactJSON(data []byte, out any, fields ...string) error {
	if cryptox.ValidateStrictJSON(data, maximumWire) != nil {
		return ErrResponse
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil || len(raw) != len(fields) {
		return ErrResponse
	}
	for _, name := range fields {
		v, ok := raw[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrResponse
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrResponse
	}
	return nil
}
func (c *Client) post(ctx context.Context, suffix string, payload []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+suffix, bytes.NewReader(payload))
	if e != nil {
		return nil, ErrInput
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	response, e := c.http.Do(req)
	if e != nil {
		return nil, ErrTransport
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, maximumWire+1))
	if e != nil || len(data) > maximumWire {
		clear(data)
		return nil, ErrResponse
	}
	if response.StatusCode != http.StatusOK {
		defer clear(data)
		var wire struct {
			Error string `json:"error"`
		}
		code := ""
		if exactJSON(data, &wire, "error") == nil {
			code = wire.Error
		}
		return nil, syncclient.NewRequestError(response.StatusCode, code)
	}
	return data, nil
}
