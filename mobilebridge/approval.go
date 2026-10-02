package mobilebridge

import (
	"encoding/json"
	"github.com/harmonia-vault/core-go/mobileworkflow"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func parseApprovalSelections(raw string) ([]mobileworkflow.ApprovalSelection, error) {
	if len(raw) == 0 || len(raw) > 8192 || !utf8.ValidString(raw) {
		return nil, errInput
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	t, e := dec.Token()
	if e != nil || t != json.Delim('[') {
		return nil, errInput
	}
	result := []mobileworkflow.ApprovalSelection{}
	environments := map[string]bool{}
	for dec.More() {
		if len(result) == 16 {
			return nil, errInput
		}
		t, e = dec.Token()
		if e != nil || t != json.Delim('{') {
			return nil, errInput
		}
		fields := map[string]string{}
		for dec.More() {
			t, e = dec.Token()
			name, ok := t.(string)
			if e != nil || !ok {
				return nil, errInput
			}
			if _, exists := fields[name]; exists {
				return nil, errInput
			}
			if name != "environmentId" && name != "role" && name != "expiresAt" {
				return nil, errInput
			}
			var value string
			if dec.Decode(&value) != nil {
				return nil, errInput
			}
			fields[name] = value
		}
		if _, e = dec.Token(); e != nil || len(fields) != 3 {
			return nil, errInput
		}
		id, role, expiry := fields["environmentId"], fields["role"], fields["expiresAt"]
		if len(id) == 0 || len(id) > 128 || environments[id] || (role != "ro" && role != "rw" && role != "admin") {
			return nil, errInput
		}
		n, e := strconv.ParseUint(expiry, 10, 63)
		if e != nil || strconv.FormatUint(n, 10) != expiry {
			return nil, errInput
		}
		environments[id] = true
		result = append(result, mobileworkflow.ApprovalSelection{EnvironmentID: id, Role: role, ExpiresAt: expiry})
	}
	if _, e = dec.Token(); e != nil || len(result) == 0 {
		return nil, errInput
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errInput
	}
	return result, nil
}
