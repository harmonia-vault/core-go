package platform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type registryOriginal struct {
	Present  bool          `json:"present"`
	Value    RegistryValue `json:"value"`
	Released bool          `json:"released,omitempty"`
}
type windowsOriginalState struct {
	Marker        string                      `json:"marker"`
	SID           string                      `json:"sid"`
	Originals     map[string]registryOriginal `json:"originals"`
	NotifyPending bool                        `json:"notifyPending,omitempty"`
}

const windowsOriginalMarker = "Harmonia Windows original values v1"

// NewPersistentWindowsProvider 在接管前持久化原始值和类型；重启不丢 REG_EXPAND_SZ。
func NewPersistentWindowsProvider(expectedSID string, store UserEnvironmentStore, statePath string) (*WindowsProvider, error) {
	if !filepath.IsAbs(statePath) {
		return nil, fmt.Errorf("original-value path must be absolute")
	}
	p, err := NewWindowsProvider(expectedSID, store)
	if err != nil {
		return nil, err
	}
	p.statePath = statePath
	content, err := os.ReadFile(statePath)
	if err == nil {
		var state windowsOriginalState
		if err := json.Unmarshal(content, &state); err != nil {
			return nil, fmt.Errorf("invalid original-value state")
		}
		if state.Marker != windowsOriginalMarker || state.SID != expectedSID || state.Originals == nil {
			return nil, fmt.Errorf("original-value SID binding mismatch")
		}
		for name, original := range state.Originals {
			if !ValidName(name) || name != strings.ToUpper(name) || strings.ContainsRune(original.Value.Value, 0) {
				return nil, fmt.Errorf("invalid original value")
			}
		}
		p.originals = state.Originals
		p.notifyPending = state.NotifyPending
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return p, nil
}
func (p *WindowsProvider) save() error {
	if p.statePath == "" && p.secret == nil {
		return nil
	}
	data, err := json.Marshal(windowsOriginalState{Marker: windowsOriginalMarker, SID: p.store.UserSID(), Originals: p.originals, NotifyPending: p.notifyPending})
	if err != nil {
		return err
	}
	if p.secret != nil {
		defer clear(data)
		return p.secret.Save("windows-originals-v1", data)
	}
	return writePrivateFile(p.statePath, append(data, '\n'), []byte(`{"marker":"`+windowsOriginalMarker+`"`))
}
func uniqueWindowsNames(names []string) error {
	seen := map[string]string{}
	for _, name := range names {
		if !ValidName(name) {
			return fmt.Errorf("invalid name")
		}
		folded := strings.ToUpper(name)
		if old, ok := seen[folded]; ok && old != name {
			return fmt.Errorf("case-insensitive Windows name collision")
		}
		seen[folded] = name
	}
	return nil
}
