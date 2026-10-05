package linuxinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/harmonia-vault/core-go/platform"
)

// unitTemplate accepts only the exact current template committed by the receipt.
func (r Receipt) unitTemplate() (platform.ServiceTemplate, error) {
	if !digest.MatchString(r.UnitSHA256) {
		return platform.ServiceTemplate{}, ErrState
	}
	unit, err := r.Plan.Unit()
	if err != nil || bytes.Count(unit.Content, []byte("\nType=")) != 1 || bytes.Count(unit.Content, []byte("\nType=exec\n")) != 1 {
		return platform.ServiceTemplate{}, ErrState
	}
	if unitDigest(unit.Content) != r.UnitSHA256 {
		return platform.ServiceTemplate{}, ErrState
	}
	return unit, nil
}

func unitDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func (r Receipt) executionType() (string, error) {
	_, err := r.unitTemplate()
	if err != nil {
		return "", err
	}
	return "exec", nil
}

// effective Type must match the receipt, not merely the unit's source bytes.
// An older manager can ignore an unknown exec directive and default to simple.
func decodeUnitType(data []byte, expected string) error {
	if expected != "exec" {
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
