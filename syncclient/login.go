package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
)

type LoginConfig struct {
	Endpoint   string
	HTTPClient *http.Client
	Email      string
	Credential string
	Now        func() time.Time
}
type LoginResult struct {
	AccountID         string `json:"accountId"`
	AccountGeneration string `json:"accountGeneration"`
	Token             string `json:"token"`
	ExpiresAt         int64  `json:"expiresAt"`
}

// Login 仅发客户端 SHA256(password) 的小写 hex。返回随机登录会话，不能
// 用它读取环境；入网批准及设备持钥会话仍是独立必要步骤。
func Login(ctx context.Context, config LoginConfig) (LoginResult, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return LoginResult{}, errors.New("login endpoint must be HTTPS without credentials, query or fragment")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(config.Credential) || config.Email == "" || len(config.Email) > 320 || strings.ContainsAny(config.Email, "\x00\r\n") {
		return LoginResult{}, errors.New("invalid login input")
	}
	client, err := secureHTTP(config.HTTPClient)
	if err != nil {
		return LoginResult{}, err
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/login"
	endpoint.RawPath = ""
	payload, _ := json.Marshal(struct {
		Email      string `json:"email"`
		Credential string `json:"credential"`
	}{config.Email, config.Credential})
	defer clear(payload)
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, errors.New("could not build login request")
	}
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return LoginResult{}, errors.New("HTTPS login failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return LoginResult{}, parseRequestError(response)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return LoginResult{}, errors.New("invalid login response size")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result LoginResult
	var extra any
	if decoder.Decode(&result) != nil || decoder.Decode(&extra) != io.EOF {
		return LoginResult{}, errors.New("login response does not match protocol")
	}
	now := time.Now()
	if config.Now != nil {
		now = config.Now()
	}
	generation, err := strconv.ParseUint(result.AccountGeneration, 10, 64)
	if !enrollmentID.MatchString(result.AccountID) || err != nil || generation == 0 || strconv.FormatUint(generation, 10) != result.AccountGeneration || result.ExpiresAt <= now.Unix() {
		return LoginResult{}, errors.New("invalid login account/session metadata")
	}
	if _, err := cryptox.DecodeBase64(result.Token, 32, 32); err != nil {
		return LoginResult{}, errors.New("invalid random login session")
	}
	return result, nil
}
func secureHTTP(source *http.Client) (*http.Client, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if source != nil {
		*client = *source
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("TLS certificate verification cannot be disabled")
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	return client, nil
}
