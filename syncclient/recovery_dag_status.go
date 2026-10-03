package syncclient

import (
	"bytes"
	"encoding/json"

	"github.com/harmonia-vault/core-go/cryptox"
)

// GET status 与 POST receipt 是不同 wire；accepted 必须明确存在，null/缺失
// 不能被普通 bool 零值变成一次“未接受”观察。
type dagStatusReceipt struct {
	value     DAGReceipt
	recovered bool
}

func (s *dagStatusReceipt) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > 4096 || strictJSONBytes(raw, &fields) != nil {
		return cryptox.ErrInvalidWire
	}
	var out DAGReceipt
	switch string(bytes.TrimSpace(fields["accepted"])) {
	case "true":
		out.Accepted = true
	case "false":
	default:
		return cryptox.ErrInvalidWire
	}
	keys := []string{"operationId", "accepted"}
	if out.Accepted {
		keys = append(keys, "sequence", "contentHash")
		if s.recovered {
			keys = append(keys, "recoveryEnrollmentHash")
		} else {
			keys = append(keys, "transitionHash")
		}
	}
	if len(fields) != len(keys) {
		return cryptox.ErrInvalidWire
	}
	for _, key := range keys {
		if len(fields[key]) == 0 {
			return cryptox.ErrInvalidWire
		}
	}
	if json.Unmarshal(fields["operationId"], &out.OperationID) != nil || !enrollmentID.MatchString(out.OperationID) {
		return cryptox.ErrInvalidWire
	}
	if out.Accepted {
		if json.Unmarshal(fields["sequence"], &out.Sequence) != nil || out.Sequence == 0 || out.Sequence > 9007199254740991 || json.Unmarshal(fields["contentHash"], &out.ContentHash) != nil || out.ContentHash == "" {
			return cryptox.ErrInvalidWire
		}
		if s.recovered {
			if json.Unmarshal(fields["recoveryEnrollmentHash"], &out.RecoveryEnrollmentHash) != nil || out.RecoveryEnrollmentHash == "" {
				return cryptox.ErrInvalidWire
			}
		} else if json.Unmarshal(fields["transitionHash"], &out.TransitionHash) != nil || out.TransitionHash == "" {
			return cryptox.ErrInvalidWire
		}
	}
	s.value = out
	return nil
}
