package syncclient

import (
	"context"
	"errors"
	"github.com/harmonia-vault/core-go/cryptox"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type DAGProtocolInfo struct {
	SupportedProtocolMajors []uint8             `json:"supportedProtocolMajors"`
	Capabilities            map[string][]string `json:"capabilities"`
}

// 显式协商major2，不因证书数字/产品版本/服务端未知字段自动降级。
func CheckDAGCapability(ctx context.Context, endpoint string, source *http.Client) error {
	return checkDAGCapabilities(ctx, endpoint, source, cryptox.RecoveryDAGCapability)
}
func checkDAGCapabilities(ctx context.Context, endpoint string, source *http.Client, required ...string) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return cryptox.ErrInvalidWire
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/protocol-info"
	u.RawPath = ""
	client, e := secureHTTP(source)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return cryptox.ErrInvalidWire
	}
	r.Header.Set("Harmonia-Protocol-Major", "2")
	r.Header.Set("Cache-Control", "no-store")
	response, e := client.Do(r)
	if e != nil {
		return errors.New("HTTPS protocol discovery failed")
	}
	defer response.Body.Close()
	if response.Header.Get("Harmonia-Protocol-Major") != "2" {
		return errors.New("protocol major2 required")
	}
	if response.StatusCode != 200 {
		return parseRequestError(response)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 16385))
	if e != nil || len(raw) > 16384 {
		return cryptox.ErrInvalidWire
	}
	var out DAGProtocolInfo
	if strictJSONBytes(raw, &out) != nil {
		return cryptox.ErrInvalidWire
	}
	major := false
	for _, m := range out.SupportedProtocolMajors {
		if m == 2 {
			major = true
		}
	}
	if !major {
		return errors.New("protocol major2 required")
	}
	for _, requiredCap := range required {
		found := false
		for _, cap := range out.Capabilities["2"] {
			if cap == requiredCap {
				found = true
			}
		}
		if !found {
			return errors.New("explicit recovery capability required")
		}
	}
	return nil
}

func CheckRecoveryOperationClosureCapability(ctx context.Context, endpoint string, source *http.Client) error {
	return checkDAGCapabilities(ctx, endpoint, source, cryptox.RecoveryDAGCapability, cryptox.RecoveryOperationClosureCapability)
}
