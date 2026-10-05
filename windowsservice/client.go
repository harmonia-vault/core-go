package windowsservice

import (
	"context"
	"encoding/json"
	"time"

	"github.com/harmonia-vault/core-go/platform"
)

type client struct {
	ctx    context.Context
	config Config
}

// NewProfileClient 返回可直接交给 NewSecureWindowsProvider 的固定 SID store。
// native 验证当前虚拟 service SID、保护配置和反向管道身份；CLI 不能直接成为 profile client。
func NewProfileClient(ctx context.Context, c Config) (platform.UserEnvironmentStore, error) {
	if ctx == nil || c.Validate() != nil {
		return nil, ErrConfiguration
	}
	if nativeClientIdentity(c) != nil {
		return nil, ErrIdentity
	}
	return &client{ctx: ctx, config: c}, nil
}
func (c *client) UserSID() string { return c.config.TargetSID }
func encodeRequest(r request) ([]byte, error) {
	fields := map[string]any{"op": r.Op}
	if r.Op != "notify" {
		fields["name"] = r.Name
	}
	if r.Op == "set" {
		fields["value"] = r.Value
		fields["expand"] = r.Expand
	}
	data, e := json.Marshal(fields)
	if e != nil {
		return nil, e
	}
	if _, e = decodeRequest(data); e != nil {
		return nil, e
	}
	return data, nil
}
func (c *client) call(r request) (response, error) {
	var out response
	data, e := encodeRequest(r)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	conn, e := nativeDialProfile(ctx, c.config)
	if e != nil {
		return out, ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if nativeServerIdentity(conn, c.config) != nil {
		return out, ErrIdentity
	}
	if writeFrame(conn, data) != nil {
		return out, ErrUnavailable
	}
	result, e := readFrame(conn)
	if e != nil {
		return out, ErrUnavailable
	}
	fields, e := flatFields(result, maxFrame)
	if e != nil || len(fields) != 4 {
		return out, ErrProtocol
	}
	for k, v := range fields {
		switch k {
		case "exists":
			e = json.Unmarshal(v, &out.Exists)
		case "value":
			e = json.Unmarshal(v, &out.Value)
		case "expand":
			e = json.Unmarshal(v, &out.Expand)
		case "code":
			e = json.Unmarshal(v, &out.Code)
		default:
			return out, ErrProtocol
		}
		if e != nil {
			return out, ErrProtocol
		}
	}
	if out.Code != "" {
		return response{}, ErrUnavailable
	}
	return out, nil
}
func (c *client) Read(name string) (platform.RegistryValue, bool, error) {
	r, e := c.call(request{Op: "read", Name: name})
	return platform.RegistryValue{Value: r.Value, Expand: r.Expand}, r.Exists, e
}
func (c *client) Set(name string, value platform.RegistryValue) error {
	_, e := c.call(request{Op: "set", Name: name, Value: value.Value, Expand: value.Expand})
	return e
}
func (c *client) Delete(name string) error {
	_, e := c.call(request{Op: "delete", Name: name})
	return e
}
func (c *client) Notify() error { _, e := c.call(request{Op: "notify"}); return e }
