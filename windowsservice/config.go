// Windows profile broker 的配置不包含密码、Vault、云地址或任意 RPC 目标。
package windowsservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/harmonia-vault/core-go/platform"
)

var (
	ErrConfiguration = errors.New("windows service configuration rejected")
	ErrIdentity      = errors.New("windows service peer identity rejected")
	ErrProtocol      = errors.New("windows profile protocol rejected")
	ErrUnavailable   = errors.New("windows profile service unavailable")
	ErrClosed        = errors.New("windows profile service closed")
	ErrCleanup       = errors.New("windows profile lease cleanup incomplete")
	ErrSyncRevert    = errors.New("windows sync pipe thread revert failed")
)

const Schema = "harmonia/windows-profile/v1"

// Config 必须从管理员保护的固定文件读取，不能由未认证 IPC 请求传入。
type Config struct {
	Schema            string `json:"schema"`
	TargetSID         string `json:"targetSID"`
	SyncServiceSID    string `json:"syncServiceSID"`
	BrokerServiceSID  string `json:"brokerServiceSID"`
	Executable        string `json:"executable"`
	SyncExecutable    string `json:"syncExecutable"`
	ConfigurationFile string `json:"configurationFile"`
}

func (c Config) Tag() string {
	h := sha256.Sum256([]byte(c.TargetSID))
	return hex.EncodeToString(h[:6])
}
func (c Config) SyncServiceName() string   { return "Harmonia-" + c.Tag() }
func (c Config) BrokerServiceName() string { return "HarmoniaProfile-" + c.Tag() }
func (c Config) TaskFolder() string        { return `\Harmonia\Profile-` + c.Tag() }
func (c Config) TaskName() string          { return c.TaskFolder() + `\Token` }
func (c Config) TokenPipe() string         { return `\\.\pipe\harmonia-profile-token-` + c.Tag() }
func (c Config) ProfilePipe() string       { return `\\.\pipe\harmonia-profile-environment-` + c.Tag() }
func (c Config) taskArguments() string     { return `token --config "` + c.ConfigurationFile + `"` }

func serviceSID(s string) bool {
	if !strings.HasPrefix(s, "S-1-5-80-") || len(s) > 184 {
		return false
	}
	parts := strings.Split(s[9:], "-")
	if len(parts) != 5 {
		return false
	}
	for _, v := range parts {
		if v == "" || (len(v) > 1 && v[0] == '0') || len(v) > 10 {
			return false
		}
		var n uint64
		for _, r := range v {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + uint64(r-'0')
		}
		if n > 0xffffffff {
			return false
		}
	}
	return true
}
func windowsPath(s string) bool {
	if len(s) < 4 || len(s) > 32760 || s[1] != ':' || s[2] != '\\' || !((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) {
		return false
	}
	for _, r := range s {
		if r < 32 || strings.ContainsRune(`/"<>|?*`, r) {
			return false
		}
	}
	for _, part := range strings.Split(s[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.ContainsRune(part, ':') || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
	}
	return true
}
func (c Config) Validate() error {
	if c.Schema != Schema || !platform.ValidSID(c.TargetSID) || !serviceSID(c.SyncServiceSID) || !serviceSID(c.BrokerServiceSID) || c.SyncServiceSID == c.BrokerServiceSID || !windowsPath(c.Executable) || !strings.HasSuffix(strings.ToLower(c.Executable), ".exe") || !windowsPath(c.SyncExecutable) || !strings.HasSuffix(strings.ToLower(c.SyncExecutable), ".exe") || !windowsPath(c.ConfigurationFile) || !strings.HasSuffix(strings.ToLower(c.ConfigurationFile), ".json") {
		return ErrConfiguration
	}
	return nil
}
func DecodeConfig(data []byte) (Config, error) {
	var c Config
	fields, err := flatFields(data, 8192)
	if err != nil {
		return c, ErrConfiguration
	}
	for k, v := range fields {
		var dst *string
		switch k {
		case "schema":
			dst = &c.Schema
		case "targetSID":
			dst = &c.TargetSID
		case "syncServiceSID":
			dst = &c.SyncServiceSID
		case "brokerServiceSID":
			dst = &c.BrokerServiceSID
		case "executable":
			dst = &c.Executable
		case "syncExecutable":
			dst = &c.SyncExecutable
		case "configurationFile":
			dst = &c.ConfigurationFile
		default:
			return c, ErrConfiguration
		}
		if json.Unmarshal(v, dst) != nil {
			return c, ErrConfiguration
		}
	}
	if len(fields) != 7 {
		return c, ErrConfiguration
	}
	return c, c.Validate()
}
