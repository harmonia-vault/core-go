package windowsaccount

import (
	"errors"
	"syscall"
)

// StartResult contains fixed operation labels and numeric Win32/SCM results,
// never error text, credentials or service account names. It is diagnostic data;
// every continuation still verifies the live service/configuration independently.
type StartResult struct {
	Stage                   string `json:"stage"`
	Succeeded               bool   `json:"succeeded"`
	CodeKnown               bool   `json:"codeKnown"`
	Code                    uint32 `json:"code"`
	StatusRead              bool   `json:"statusRead"`
	State                   uint32 `json:"state"`
	StartType               uint32 `json:"startType"`
	Win32ExitCode           uint32 `json:"win32ExitCode"`
	ServiceSpecificExitCode uint32 `json:"serviceSpecificExitCode"`
}

func startResult(stage string, err error) StartResult {
	r := StartResult{Stage: stage, Succeeded: err == nil, CodeKnown: err == nil}
	var code syscall.Errno
	if err != nil && errors.As(err, &code) {
		r.CodeKnown = true
		r.Code = uint32(code)
	}
	return r
}

// mayStartReceipt permits one explicitly requested start of a currently stopped
// service. The only continuation covered here is the old/new durable start-service
// intent with current Demand start; it never treats a running or unknown state as
// permission to start again. Automatic/crash recovery is not implemented here.
func mayStartReceipt(r Receipt, state, startType uint32) (resume bool, allowed bool) {
	const stopped, demand, disabled = 1, 3, 4
	if r.Stage != "installed-disabled" || !r.ServiceCreated || state != stopped {
		return false, false
	}
	if r.Pending == "" {
		return false, startType == disabled && r.LastStart == nil
	}
	if r.Pending != "start-service" || startType != demand {
		return false, false
	}
	if r.LastStart != nil {
		switch r.LastStart.Stage {
		case "change-demand", "resume-manual", "start-service", "wait-running":
		default:
			return false, false
		}
	}
	return true, true
}
