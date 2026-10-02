package localipc

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"
)

type SharedWriteRequest struct {
	RequestID, Command, EnvironmentID, Name string
	Value                                   *string
	Selected                                map[string]string
}
type SharedWriteResult struct {
	RequestID string   `json:"requestId"`
	Total     int      `json:"total"`
	Accepted  int      `json:"accepted"`
	Applied   bool     `json:"applied"`
	Sequences []uint64 `json:"sequences"`
}

func isSharedWrite(command string) bool {
	return command == "put" || command == "delete" || command == "import" || command == "write-retry"
}
func validateSharedRequest(r Request) error {
	if r.Version != Version || !idPattern.MatchString(r.RequestID) || len(r.RequestID) > 64 || r.Priority != nil {
		return ErrProtocol
	}
	validName := func(name string) bool {
		return namePattern.MatchString(name) && !strings.HasPrefix(strings.ToUpper(name), "__HARMONIA_")
	}
	validValue := func(value string) bool {
		return len(value) <= 65536 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
	}
	if r.Command == "write-retry" {
		if r.EnvironmentID != "" || r.Name != "" || r.Value != nil || len(r.Selected) != 0 {
			return ErrProtocol
		}
		return nil
	}
	if !idPattern.MatchString(r.EnvironmentID) {
		return ErrProtocol
	}
	switch r.Command {
	case "put":
		if !validName(r.Name) || r.Value == nil || !validValue(*r.Value) || len(r.Selected) != 0 {
			return ErrProtocol
		}
	case "delete":
		if !validName(r.Name) || r.Value != nil || len(r.Selected) != 0 {
			return ErrProtocol
		}
	case "import":
		if r.Name != "" || r.Value != nil || len(r.Selected) < 1 || len(r.Selected) > 16 {
			return ErrProtocol
		}
		size := 0
		for name, value := range r.Selected {
			if !validName(name) || !validValue(value) {
				return ErrProtocol
			}
			size += len(value)
		}
		if size > 65536 {
			return ErrProtocol
		}
	default:
		return ErrProtocol
	}
	return nil
}
func (s *Server) dispatchShared(ctx context.Context, r Request, now time.Time) Response {
	response := Response{Version: Version}
	if s.config.OnlineWrite == nil || s.config.Engine.State().Synthetic {
		response.Code = "shared_write_unavailable"
		return response
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result, err := s.config.OnlineWrite(operationCtx, SharedWriteRequest{RequestID: r.RequestID, Command: r.Command, EnvironmentID: r.EnvironmentID, Name: r.Name, Value: r.Value, Selected: r.Selected})
	response.Write = &result
	// 在线刷新发现失权时，写失败也必须执行逐项恢复。
	if reconcileErr := s.config.Engine.Reconcile(ctx, s.config.Provider, now); reconcileErr != nil {
		response.Code = "provider_or_persistence_failed"
		return response
	}
	if err != nil {
		response.Code = "shared_write_pending_or_rejected"
		return response
	}
	response.OK = true
	return response
}
