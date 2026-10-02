package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/harmonia-vault/core-go/localstate"
)

const fragmentMarker = "# Harmonia managed fragment v1\n"
const stateMarker = "Harmonia POSIX provider v1"

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ValidName 仅接受可移植的 shell 环境名；不枚举用户环境。
func ValidName(name string) bool {
	return namePattern.MatchString(name) && !strings.HasPrefix(strings.ToUpper(name), "__HARMONIA_")
}

// ShellQuote 使用单引号编码 shell 字面量，不执行值里的命令或展开。
func ShellQuote(value string) (string, error) {
	if strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("NUL is not an environment value")
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'", nil
}

// RenderPOSIXFragment 每个 shell 自己记录首次接管的值。released 逐 key 恢复，绝不恢复整个文件。
func RenderPOSIXFragment(identity string, desired map[string]string, released []string) ([]byte, error) {
	return renderPOSIXFragment(identity, desired, released, false, nil)
}

func renderPOSIXFragment(identity string, desired map[string]string, released []string, paused bool, revisions map[string]uint64) ([]byte, error) {
	sum := sha256.Sum256([]byte(identity))
	prefix := "__HARMONIA_" + strings.ToUpper(hex.EncodeToString(sum[:8])) + "_"
	keys := make([]string, 0, len(desired))
	for name, value := range desired {
		if !ValidName(name) {
			return nil, fmt.Errorf("invalid environment name")
		}
		if _, err := ShellQuote(value); err != nil {
			return nil, err
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString(fragmentMarker)
	out.WriteString("# 请通过交互 shell 刷新；不能从外部修改已有进程环境。\n")
	for _, name := range keys {
		seen, exists, value := prefix+"SEEN_"+name, prefix+"EXISTS_"+name, prefix+"VALUE_"+name
		quoted, _ := ShellQuote(desired[name])
		revision := revisions[name]
		if revision == 0 {
			revision = 1
		}
		last := prefix + "REV_" + name
		if paused {
			fmt.Fprintf(&out, "if [ \"${%s-}\" != %d ]; then\n", last, revision)
		}
		fmt.Fprintf(&out, "if [ \"${%s-}\" != 1 ]; then\n  %s=${%s+x}\n  %s=\"${%s-}\"\n  %s=1\nfi\nexport %s=%s\n", seen, exists, name, value, name, seen, name, quoted)
		fmt.Fprintf(&out, "%s=%d\n", last, revision)
		if paused {
			out.WriteString("fi\n")
		}
	}
	releasedSet := map[string]bool{}
	for _, name := range released {
		if !ValidName(name) {
			return nil, fmt.Errorf("invalid released name")
		}
		if _, active := desired[name]; active {
			return nil, fmt.Errorf("key cannot be active and released")
		}
		releasedSet[name] = true
	}
	keys = keys[:0]
	for name := range releasedSet {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		seen, exists, value := prefix+"SEEN_"+name, prefix+"EXISTS_"+name, prefix+"VALUE_"+name
		last := prefix + "REV_" + name
		fmt.Fprintf(&out, "if [ \"${%s-}\" = 1 ]; then\n  if [ \"${%s-}\" = x ]; then\n    export %s=\"${%s-}\"\n  else\n    unset %s\n  fi\n  unset %s %s %s %s\nfi\n", seen, exists, name, value, name, seen, exists, value, last)
	}
	return []byte(out.String()), nil
}

type posixState struct {
	Marker    string            `json:"marker"`
	Desired   map[string]string `json:"desired"`
	Released  map[string]bool   `json:"released"`
	Paused    bool              `json:"paused"`
	Revisions map[string]uint64 `json:"revisions"`
}

// POSIXProvider 保存下发目标，原值仍由每个 shell 在首次 source 时采集。
// baseline 是测试或明确提供的快照；这里绝不调用 os.Environ。
type POSIXProvider struct {
	mu       sync.Mutex
	path     string
	baseline map[string]string
	state    posixState
}

func NewPOSIXProvider(fragmentPath string, baseline map[string]string) (*POSIXProvider, error) {
	if !filepath.IsAbs(fragmentPath) {
		return nil, fmt.Errorf("fragment path must be absolute")
	}
	p := &POSIXProvider{path: fragmentPath, baseline: map[string]string{}, state: posixState{Marker: stateMarker, Desired: map[string]string{}, Released: map[string]bool{}, Revisions: map[string]uint64{}}}
	for name, value := range baseline {
		if !ValidName(name) {
			return nil, fmt.Errorf("invalid baseline name")
		}
		if _, err := ShellQuote(value); err != nil {
			return nil, err
		}
		p.baseline[name] = value
	}
	content, err := os.ReadFile(fragmentPath + ".state.json")
	if err == nil {
		var state posixState
		if err := json.Unmarshal(content, &state); err != nil {
			return nil, fmt.Errorf("invalid provider state")
		}
		if state.Marker != stateMarker || state.Desired == nil || state.Released == nil {
			return nil, fmt.Errorf("invalid provider state")
		}
		if state.Revisions == nil {
			state.Revisions = map[string]uint64{}
		}
		for name := range state.Desired {
			if state.Revisions[name] == 0 {
				state.Revisions[name] = 1
			}
		}
		p.state = state
		if err := p.writeFragment(state); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return p, nil
}

func (p *POSIXProvider) Snapshot(ctx context.Context, names []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result := map[string]string{}
	for _, name := range names {
		if !ValidName(name) {
			return nil, fmt.Errorf("invalid name")
		}
		if value, ok := p.state.Desired[name]; ok {
			result[name] = value
		} else if value, ok := p.baseline[name]; ok {
			result[name] = value
		}
	}
	return result, nil
}

func (p *POSIXProvider) Apply(ctx context.Context, changes []localstate.Change) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	next := posixState{Marker: stateMarker, Desired: map[string]string{}, Released: map[string]bool{}, Paused: p.state.Paused, Revisions: map[string]uint64{}}
	for name, revision := range p.state.Revisions {
		next.Revisions[name] = revision
	}
	for name, value := range p.state.Desired {
		next.Desired[name] = value
	}
	for name, value := range p.state.Released {
		next.Released[name] = value
	}
	for _, change := range changes {
		if !ValidName(change.Name) {
			return fmt.Errorf("invalid name")
		}
		if change.Release || change.Value == nil {
			if _, active := next.Desired[change.Name]; active {
				if next.Revisions[change.Name] == ^uint64(0) {
					return fmt.Errorf("local revision exhausted")
				}
				next.Revisions[change.Name]++
			}
			delete(next.Desired, change.Name)
			next.Released[change.Name] = true
			continue
		}
		if _, err := ShellQuote(*change.Value); err != nil {
			return err
		}
		if old, active := next.Desired[change.Name]; !active || old != *change.Value {
			if next.Revisions[change.Name] == ^uint64(0) {
				return fmt.Errorf("local revision exhausted")
			}
			next.Revisions[change.Name]++
		}
		next.Desired[change.Name] = *change.Value
		delete(next.Released, change.Name)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	// 写 state 后写 fragment；若中断，重新打开会根据 state 重建 fragment。
	if err := writePrivateFile(p.path+".state.json", append(data, '\n'), []byte(`{"marker":"`+stateMarker+`"`)); err != nil {
		return err
	}
	p.state = next
	return p.writeFragment(next)
}

func (p *POSIXProvider) writeFragment(state posixState) error {
	released := make([]string, 0, len(state.Released))
	for name, release := range state.Released {
		if release {
			released = append(released, name)
		}
	}
	data, err := renderPOSIXFragment(p.path, state.Desired, released, state.Paused, state.Revisions)
	if err != nil {
		return err
	}
	return writePrivateFile(p.path, data, []byte(fragmentMarker))
}

// RenderShellHook 只生成供用户审查的片段，不编辑启动文件。
// sh 无可移植的 prompt hook，因此只提供开始会话及显式刷新。
func RenderShellHook(shell, fragmentPath string) (string, error) {
	if !filepath.IsAbs(fragmentPath) {
		return "", fmt.Errorf("fragment path must be absolute")
	}
	quoted, err := ShellQuote(fragmentPath)
	if err != nil {
		return "", err
	}
	base := "harmonia_refresh() { [ ! -r " + quoted + " ] || . " + quoted + "; }\nharmonia_refresh\n"
	switch shell {
	case "sh":
		return "# sh 会话开始刷新；之后可显式调用 harmonia_refresh。\n" + base, nil
	case "bash":
		return base + "if [ \"${__HARMONIA_BASH_HOOK_INSTALLED-}\" != 1 ]; then\n  __HARMONIA_BASH_HOOK_INSTALLED=1\nif [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a '* ]]; then\n  PROMPT_COMMAND=(harmonia_refresh \"${PROMPT_COMMAND[@]}\")\nelse\n  PROMPT_COMMAND=\"harmonia_refresh${PROMPT_COMMAND:+; $PROMPT_COMMAND}\"\nfi\nfi\n", nil
	case "zsh":
		return base + "autoload -Uz add-zsh-hook\nadd-zsh-hook precmd harmonia_refresh\n", nil
	default:
		return "", fmt.Errorf("unsupported shell")
	}
}
