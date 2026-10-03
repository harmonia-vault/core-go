package linuxinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/harmonia-vault/core-go/platform"
)

// unitTemplate keeps the persisted full-unit digest authoritative. Fresh plans
// use exec. A historical receipt may select only the exact preceding simple
// template for the same validated plan; no installed file supplies a template.
// The receipt digest must never be replaced to upgrade an existing installation.
func (r Receipt) unitTemplate() (platform.ServiceTemplate, error) {
	if !digest.MatchString(r.UnitSHA256) {
		return platform.ServiceTemplate{}, ErrState
	}
	unit, err := r.Plan.Unit()
	if err != nil || bytes.Count(unit.Content, []byte("\nType=")) != 1 || bytes.Count(unit.Content, []byte("\nType=exec\n")) != 1 {
		return platform.ServiceTemplate{}, ErrState
	}
	if unitDigest(unit.Content) == r.UnitSHA256 {
		return unit, nil
	}
	legacy := bytes.Replace(unit.Content, []byte("\nType=exec\n"), []byte("\nType=simple\n"), 1)
	if unitDigest(legacy) != r.UnitSHA256 {
		return platform.ServiceTemplate{}, ErrState
	}
	unit.Content = legacy
	return unit, nil
}

func unitDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func (r Receipt) executionType() (string, error) {
	unit, err := r.unitTemplate()
	if err != nil {
		return "", err
	}
	if bytes.Contains(unit.Content, []byte("\nType=exec\n")) {
		return "exec", nil
	}
	return "simple", nil
}

// effective Type must match the receipt, not merely the unit's source bytes.
// An older manager can ignore an unknown exec directive and default to simple.
func decodeUnitType(data []byte, expected string) error {
	if expected != "exec" && expected != "simple" {
		return ErrState
	}
	if !bytes.Equal(data, []byte("Type=exec\n")) && !bytes.Equal(data, []byte("Type=simple\n")) {
		return ErrState
	}
	if !bytes.Equal(data, []byte("Type="+expected+"\n")) {
		return ErrUnsupported
	}
	return nil
}

func decodeUnitTypeResponse(stdout, stderr []byte, expected string) error {
	if len(stderr) != 0 {
		return ErrState
	}
	return decodeUnitType(stdout, expected)
}
