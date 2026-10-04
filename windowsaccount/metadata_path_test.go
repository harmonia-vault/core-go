package windowsaccount

import (
	"errors"
	"testing"
)

func TestMetadataNTPathRestrictsNamespace(t *testing.T) {
	for _, p := range []string{`C:\`, `C:\Program Files\Harmonia`, `d:\配置\Vault`} {
		got, e := metadataNTPath(p)
		if e != nil || got != `\??\`+p {
			t.Fatalf("canonical local path rejected: %q", p)
		}
	}
	for _, p := range []string{"", `C:relative`, `\\server\share`, `\\?\C:\x`, `\??\C:\x`, `C:/x`, `C:\x:stream`, `C:\..\x`, `C:\x\\y`, `C:\x.`, `C:\x `, "C:\\x\x00y", `C:\x\`} {
		got, e := metadataNTPath(p)
		if !errors.Is(e, ErrPlan) || got != "" {
			t.Fatalf("noncanonical namespace accepted: %q", p)
		}
	}
}
