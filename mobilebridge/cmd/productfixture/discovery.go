package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
)

// 只作合成CLI发现；此对象没有trust字段，不持有包/密文/凭据，也不参与业务验签。
type publicScope struct {
	AccountGeneration string `json:"accountGeneration"`
	ManagerDeviceID   string `json:"managerDeviceId"`
	EnvironmentID     string `json:"environmentId"`
}
type publicDiscovery struct {
	mu                                    sync.Mutex
	account, generation                   string
	sequence                              uint64
	haveInitialization, havePull, blocked bool
	claimedInitialization, claimedPull    bool
	result                                *publicScope
}

var discoveryIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var discoveryDeviceID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var discoveryHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var discoveryCompletePath = regexp.MustCompile(`^/v1/accounts/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})/vault-initializations/([A-Za-z0-9][A-Za-z0-9._:-]{0,63})/complete$`)
var discoveryPullPath = regexp.MustCompile(`^/v1/accounts/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})/pull$`)

func discoveryDecimal(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n > 0 && n <= 9007199254740991 && strconv.FormatUint(n, 10) == value
}
func discoveryBytes(value string, size int) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	defer clear(raw)
	return err == nil && len(raw) == size && base64.RawURLEncoding.EncodeToString(raw) == value
}
func (d *publicDiscovery) snapshot() (publicScope, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.blocked || d.result == nil {
		return publicScope{}, false
	}
	return *d.result, true
}
func (d *publicDiscovery) observe(method, path string, status int, body []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.blocked || d.result != nil || status != 200 || len(body) == 0 || len(body) > 1048576 {
		return false
	}
	if parts := discoveryCompletePath.FindStringSubmatch(path); method == "POST" && parts != nil {
		if d.haveInitialization {
			return false
		} // 一次来源；后续complete不能替换。
		var value struct {
			State          string   `json:"state"`
			ChallengeID    string   `json:"challengeId"`
			IdempotencyKey string   `json:"idempotencyKey"`
			Nonce          string   `json:"nonce"`
			ExpiresAt      int64    `json:"expiresAt"`
			ProposalHash   string   `json:"proposalHash"`
			SigningPayload []string `json:"signingPayload"`
			Sequence       *uint64  `json:"sequence"`
			Replayed       *bool    `json:"replayed"`
		}
		if decodeStrict(body, &value) != nil || value.State != "complete" || value.Sequence == nil || *value.Sequence != 1 ||
			value.Replayed == nil || *value.Replayed || !discoveryIdentifier.MatchString(value.ChallengeID) || value.IdempotencyKey != parts[2] ||
			!discoveryBytes(value.Nonce, 32) || value.ExpiresAt <= 0 || !discoveryHash.MatchString(value.ProposalHash) || len(value.SigningPayload) != 8 {
			d.blocked = true
			return false
		}
		p := value.SigningPayload
		if p[0] != "harmonia/vault-initialize/v1" || p[1] != parts[1] || !discoveryDecimal(p[2]) ||
			!discoveryHash.MatchString(p[3]) || p[4] != value.ChallengeID || p[5] != value.Nonce ||
			p[6] != strconv.FormatInt(value.ExpiresAt, 10) || p[7] != value.ProposalHash {
			d.blocked = true
			return false
		}
		d.account, d.generation, d.sequence, d.haveInitialization = parts[1], p[2], *value.Sequence, true
		return true
	}
	if parts := discoveryPullPath.FindStringSubmatch(path); method == "GET" && parts != nil {
		if d.havePull {
			return false
		}
		d.havePull = true
		if !d.haveInitialization || parts[1] != d.account {
			d.blocked = true
			return false
		}
		// opaque evidence/events暂存只用于严格JSON边界；不保存/输出、不声称已验签。
		var value struct {
			AccountID         string `json:"accountId"`
			AccountGeneration string `json:"accountGeneration"`
			Sequence          uint64 `json:"sequence"`
			Grants            []struct {
				Grant struct {
					AccountID          string `json:"accountId"`
					AccountGeneration  string `json:"accountGeneration"`
					IssuerDeviceID     string `json:"issuerDeviceId"`
					SubjectDeviceID    string `json:"subjectDeviceId"`
					SigningPublicKey   string `json:"subjectSigningPublicKey"`
					ReceivingPublicKey string `json:"subjectReceivingPublicKey"`
					EnvironmentID      string `json:"environmentId"`
					KeyVersion         string `json:"keyVersion"`
					GrantGeneration    string `json:"grantGeneration"`
					Role               string `json:"role"`
					ExpiresAt          string `json:"expiresAt"`
					IdempotencyKey     string `json:"idempotencyKey"`
					Envelope           string `json:"envelope"`
				} `json:"grant"`
				Signature string `json:"signature"`
			} `json:"grants"`
			Events            []json.RawMessage `json:"events"`
			EnvironmentEvents []json.RawMessage `json:"environmentEvents"`
			IssuerEvidence    json.RawMessage   `json:"issuerEvidence"`
		}
		defer func() {
			clear(value.IssuerEvidence)
			for _, event := range value.Events {
				clear(event)
			}
			for _, event := range value.EnvironmentEvents {
				clear(event)
			}
		}()
		if decodeStrict(body, &value) != nil || value.AccountID != d.account || value.AccountGeneration != d.generation ||
			value.Sequence != d.sequence || len(value.Grants) != 1 || value.Events == nil || len(value.Events) != 0 ||
			value.EnvironmentEvents == nil || len(value.EnvironmentEvents) != 0 || len(value.IssuerEvidence) == 0 || bytes.Equal(value.IssuerEvidence, []byte("null")) {
			d.blocked = true
			return false
		}
		signed := value.Grants[0]
		g := signed.Grant
		if g.AccountID != d.account || g.AccountGeneration != d.generation || !discoveryDeviceID.MatchString(g.SubjectDeviceID) ||
			g.IssuerDeviceID != g.SubjectDeviceID || !discoveryIdentifier.MatchString(g.EnvironmentID) ||
			g.KeyVersion != "1" || g.GrantGeneration != "1" || g.Role != "admin" || g.ExpiresAt != "0" ||
			!discoveryIdentifier.MatchString(g.IdempotencyKey) || !discoveryBytes(g.SigningPublicKey, 32) ||
			!discoveryBytes(g.ReceivingPublicKey, 32) || g.SigningPublicKey == g.ReceivingPublicKey ||
			!discoveryBytes(g.Envelope, 80) || !discoveryBytes(signed.Signature, 64) {
			d.blocked = true
			return false
		}
		d.result = &publicScope{AccountGeneration: d.generation, ManagerDeviceID: g.SubjectDeviceID, EnvironmentID: g.EnvironmentID}
		return true
	}
	return false
}

// 旁路观察原Body读流，不改body、headers、status或业务路径。完整body不留在discovery。
type discoveryBody struct {
	io.ReadCloser
	data               []byte
	overflow, observed bool
	observe            func([]byte)
	discard            func()
}

func (b *discoveryBody) finish() {
	if b.observed {
		return
	}
	b.observed = true
	defer func() { clear(b.data); b.data = nil }()
	if !b.overflow {
		b.observe(b.data)
	} else {
		b.discard()
	}
}
func (b *discoveryBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.observed && !b.overflow && n > 0 {
		if len(b.data)+n > 1048576 {
			b.overflow = true
			clear(b.data)
			b.data = nil
		} else {
			b.data = append(b.data, p[:n]...)
		}
	}
	if err == io.EOF {
		b.finish()
	}
	return n, err
}
func (b *discoveryBody) Close() error {
	// 未读完不能发布发现；无论正常/中断都清暂存。
	if !b.observed {
		b.discard()
		clear(b.data)
		b.data = nil
		b.observed = true
	}
	return b.ReadCloser.Close()
}
func (d *publicDiscovery) response(r *http.Response) {
	if r.StatusCode != 200 || r.Request == nil || r.Request.URL == nil || r.Body == nil {
		return
	}
	method, path := r.Request.Method, r.Request.URL.Path
	if (method != "POST" || !discoveryCompletePath.MatchString(path)) && (method != "GET" || !discoveryPullPath.MatchString(path)) {
		return
	}
	d.mu.Lock()
	claimed := d.claimedPull
	if method == "POST" {
		claimed = d.claimedInitialization
	}
	frozen := d.blocked || d.result != nil || claimed
	if !frozen {
		if method == "POST" {
			d.claimedInitialization = true
		} else {
			d.claimedPull = true
		}
	}
	d.mu.Unlock()
	if frozen {
		return
	}
	r.Body = &discoveryBody{ReadCloser: r.Body,
		observe: func(body []byte) { d.observe(method, path, r.StatusCode, body) },
		discard: func() { d.mu.Lock(); defer d.mu.Unlock(); d.blocked = true }}
}
func withDiscovery(discovery *publicDiscovery, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test/discovery" {
			fallback.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"error":"synthetic_discovery_request_invalid"}`)
			return
		}
		value, ok := discovery.snapshot()
		if !ok {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"error":"synthetic_discovery_unavailable"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
	})
}
