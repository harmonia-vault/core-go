//go:build darwin || linux

package main

import (
	"github.com/harmonia-vault/core-go/localkeys"
	"testing"
)

func TestProtectedDaemonRejectsObsoleteEnrollmentVersions(t *testing.T) {
	for _, version := range []string{"", "1", "2", "3", "4"} {
		if verifier, err := verifiedStoredContext(localkeys.TrustContext{Accepted: true, CertificateVersion: version}, localkeys.DeviceKeys{}); err == nil {
			verifier.Close()
			t.Fatalf("obsolete certificate %q enabled daemon", version)
		}
	}
}
