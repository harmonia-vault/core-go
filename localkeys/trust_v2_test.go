package localkeys

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObsoleteTrustVersionsAreRejectedWithoutMigration(t *testing.T) {
	v := openTest(t, testConfig(t))
	current := trustFixture(t, v)
	for _, version := range []string{"", "1", "2", "3", "4"} {
		old := current
		old.CertificateVersion = version
		raw, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		if err = v.SaveTrustContext(old); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("old version %q saved: %v", version, err)
		}
		if err = v.Save("trust-v1", raw); err != nil {
			t.Fatal(err)
		}
		if _, err = v.LoadTrustContext(); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("old version %q loaded: %v", version, err)
		}
	}
}
