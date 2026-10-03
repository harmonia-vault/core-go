package cryptox

import (
	"encoding/json"
	"reflect"
)

func strictDAGObjectOptional(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if ValidateStrictJSON(data, MaxRecoveryAuthorityBytes) != nil {
		return nil, ErrInvalidWire
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return nil, ErrInvalidWire
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return nil, ErrInvalidWire
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, ErrInvalidWire
		}
	}
	return m, nil
}
func DecodeRecoveryDependencyBundle(data []byte) (RecoveryDependencyBundle, error) {
	var b RecoveryDependencyBundle
	m, e := strictDAGObject(data, "initialization", "records")
	if e != nil {
		return b, e
	}
	if validateRecoveryJSONShape(m["initialization"], reflect.TypeOf(b.Initialization), nil) != nil || strictDAGDecode(data, &b) != nil {
		return b, ErrInvalidWire
	}
	if _, e = b.Initialization.Hash(); e != nil {
		return b, e
	}
	_, e = recordRows(b.Records)
	return b, e
}
func DecodeRecoveryTransitionCommandV2(data []byte) (RecoveryTransitionCommandV2, error) {
	var c RecoveryTransitionCommandV2
	m, e := strictDAGObject(data, "submission", "dependencyBundle")
	if e != nil {
		return c, e
	}
	b, e := DecodeRecoveryDependencyBundle(m["dependencyBundle"])
	if e != nil {
		return c, e
	}
	if validateRecoveryJSONShape(m["submission"], reflect.TypeOf(c.Submission), map[string]bool{"$.issuerEvidence": true, "$.legacyState": true}) != nil || strictDAGDecode(m["submission"], &c.Submission) != nil {
		return c, ErrInvalidWire
	}
	c.DependencyBundle = b
	if _, e = c.Submission.Transition.SigningBytes(); e != nil {
		return c, e
	}
	if _, e = RecoveryTransitionHashV2(c.Submission); e != nil {
		return c, e
	}
	return c, nil
}
func DecodeRecoveredDeviceCommandV2(data []byte) (RecoveredDeviceCommandV2, error) {
	var c RecoveredDeviceCommandV2
	m, e := strictDAGObject(data, "submission", "dependencyBundle")
	if e != nil {
		return c, e
	}
	b, e := DecodeRecoveryDependencyBundle(m["dependencyBundle"])
	if e != nil {
		return c, e
	}
	if validateRecoveryJSONShape(m["submission"], reflect.TypeOf(c.Submission), nil) != nil || strictDAGDecode(m["submission"], &c.Submission) != nil {
		return c, ErrInvalidWire
	}
	c.DependencyBundle = b
	s := c.Submission
	if s.CertificateVersion != "5" || len(s.Capabilities) != 1 || s.Capabilities[0] != RecoveryDAGCapability {
		return c, ErrInvalidWire
	}
	if _, e = s.Enrollment.SigningBytes(); e != nil {
		return c, e
	}
	if _, e = RecoveredDeviceReferenceHashV2(s); e != nil {
		return c, e
	}
	return c, nil
}
