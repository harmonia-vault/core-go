package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/harmonia-vault/core-go/localkeys"
)

const securePOSIXSchema = "harmonia/secure-posix-provider/v1"

// 仅内部 I/O 接口；正式公开构造器仍只接受受保护 Vault。
type securePOSIXVault interface {
	Directory() string
	Load(string) ([]byte, error)
	Save(string, []byte) error
	WriteEnvironmentFragment([]byte) error
}

type securePOSIXState struct {
	Schema       string     `json:"schema"`
	FragmentPath string     `json:"fragmentPath"`
	State        posixState `json:"state"`
}

func decodeSecure(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return fmt.Errorf("invalid encrypted provider state")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("invalid encrypted provider state")
	}
	return nil
}
func validatePOSIXState(state posixState) error {
	if state.Marker != stateMarker || state.Desired == nil || state.Released == nil || state.Revisions == nil {
		return fmt.Errorf("invalid encrypted provider state")
	}
	for name, value := range state.Desired {
		if !ValidName(name) || strings.ContainsRune(value, 0) || state.Revisions[name] == 0 || state.Released[name] {
			return fmt.Errorf("invalid encrypted provider state")
		}
	}
	for name := range state.Released {
		if !ValidName(name) {
			return fmt.Errorf("invalid encrypted provider state")
		}
	}
	for name := range state.Revisions {
		if !ValidName(name) {
			return fmt.Errorf("invalid encrypted provider state")
		}
	}
	return nil
}

// NewSecurePOSIXProvider 将辅助元数据放入 Vault AEAD；不迁移明文 fixture。
// fragment 必须是同 Vault 目录中的固定 environment.sh，写入沿用受保护目录句柄。
func NewSecurePOSIXProvider(fragmentPath string, vault *localkeys.Vault) (*POSIXProvider, error) {
	if vault == nil {
		return nil, fmt.Errorf("fragment must be bound to protected vault directory")
	}
	return loadSecurePOSIXProvider(fragmentPath, vault, true)
}
func loadSecurePOSIXProvider(fragmentPath string, vault securePOSIXVault, reapply bool) (*POSIXProvider, error) {
	if vault == nil || fragmentPath != filepath.Join(vault.Directory(), "environment.sh") {
		return nil, fmt.Errorf("fragment must be bound to protected vault directory")
	}
	if _, err := os.Lstat(fragmentPath + ".state.json"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("plaintext fixture metadata cannot enter secure provider")
	}
	p := &POSIXProvider{path: fragmentPath, baseline: map[string]string{}, secret: vault, state: posixState{Marker: stateMarker, Desired: map[string]string{}, Released: map[string]bool{}, Revisions: map[string]uint64{}}}
	data, err := vault.Load("provider-v1")
	if err == nil {
		defer clear(data)
		var record securePOSIXState
		if err := decodeSecure(data, &record); err != nil {
			return nil, err
		}
		if record.Schema != securePOSIXSchema || record.FragmentPath != fragmentPath {
			return nil, fmt.Errorf("encrypted provider path binding mismatch")
		}
		if err := validatePOSIXState(record.State); err != nil {
			return nil, err
		}
		p.state = record.State
		if reapply {
			if err := p.writeFragment(p.state); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return p, nil
}
func (p *POSIXProvider) saveState(state posixState) error {
	if p.secret != nil {
		if err := validatePOSIXState(state); err != nil {
			return err
		}
		data, err := json.Marshal(securePOSIXState{Schema: securePOSIXSchema, FragmentPath: p.path, State: state})
		if err != nil {
			return err
		}
		defer clear(data)
		return p.secret.Save("provider-v1", data)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writePrivateFile(p.path+".state.json", append(data, '\n'), []byte(`{"marker":"`+stateMarker+`"`))
}

// NewSecureWindowsProvider 将逐 key 原值、存在性与 REG_EXPAND_SZ 类型存入 AEAD。
// 非 Windows 测试使用隔离 MemoryUserStore；实际 Windows 必须匹配 Vault 的目标 SID。
func NewSecureWindowsProvider(expectedSID string, store UserEnvironmentStore, vault *localkeys.Vault) (*WindowsProvider, error) {
	if vault == nil || runtime.GOOS == "windows" && vault.TargetUserID() != expectedSID {
		return nil, fmt.Errorf("encrypted original-value SID binding mismatch")
	}
	p, err := NewWindowsProvider(expectedSID, store)
	if err != nil {
		return nil, err
	}
	p.secret = vault
	data, err := vault.Load("windows-originals-v1")
	if err == nil {
		defer clear(data)
		var state windowsOriginalState
		if err := decodeSecure(data, &state); err != nil {
			return nil, err
		}
		if state.Marker != windowsOriginalMarker || state.SID != expectedSID || state.Originals == nil {
			return nil, fmt.Errorf("encrypted original-value SID binding mismatch")
		}
		for name, original := range state.Originals {
			if !ValidName(name) || name != strings.ToUpper(name) || strings.ContainsRune(original.Value.Value, 0) {
				return nil, fmt.Errorf("invalid encrypted original value")
			}
		}
		p.originals = state.Originals
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return p, nil
}
