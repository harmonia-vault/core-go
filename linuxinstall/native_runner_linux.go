//go:build linux

package linuxinstall

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type runtimeActions interface {
	show(context.Context, Plan) (UnitState, error)
	control(context.Context, string, Plan) error
	unitType(context.Context, Plan, string) error
	drained(context.Context, Plan) error
	enrollment(context.Context, Plan) error
	logout(context.Context, Plan) error
}
type nativeActions struct{ lease *AdminLease }

func (n nativeActions) show(ctx context.Context, p Plan) (UnitState, error) {
	s, e := ShowUnit(ctx, p)
	if e == nil && s.ActiveState == "active" {
		e = verifyServiceProcess(p, s.MainPID)
	}
	return s, e
}
func (n nativeActions) unitType(ctx context.Context, p Plan, expected string) error {
	if n.lease.guard() != nil {
		return ErrPermission
	}
	if expected != "exec" && expected != "simple" || p.Validate() != nil {
		return ErrState
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all", "--property=Type", p.UnitName)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out := boundedOutput{limit: maxSystemctlOutput}
	discard := boundedOutput{limit: maxSystemctlOutput}
	cmd.Stdout, cmd.Stderr = &out, &discard
	if cmd.Run() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n.lease.guard() != nil {
		return ErrPermission
	}
	return decodeUnitTypeResponse(out.b.Bytes(), discard.b.Bytes(), expected)
}

func (n nativeActions) drained(ctx context.Context, p Plan) error { return CheckDrained(ctx, p) }
func (n nativeActions) control(ctx context.Context, op string, p Plan) error {
	if n.lease.guard() != nil {
		return ErrPermission
	}
	if op == "stop" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	args := []string{"--system", "--no-pager"}
	switch op {
	case "daemon-reload":
		args = append(args, op)
	case "enable", "start", "stop":
		args = append(args, op, p.UnitName)
	default:
		return ErrPlan
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	out := boundedOutput{limit: maxSystemctlOutput}
	discard := boundedOutput{limit: maxSystemctlOutput}
	cmd.Stdout = &out
	cmd.Stderr = &discard
	if cmd.Run() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrState
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return n.lease.guard()
}
func (n nativeActions) logout(ctx context.Context, p Plan) error {
	return n.lease.RunOfflineLogout(ctx, p)
}
func (n nativeActions) enrollment(ctx context.Context, p Plan) error {
	if n.lease.guard() != nil {
		return ErrPermission
	}
	r, e := n.lease.LoadReceipt()
	if e != nil || r.Plan != p {
		return ErrState
	}
	u, e := user.Lookup(p.Input.UserName)
	if e != nil || u.Uid != p.Input.UID || u.Gid != p.Input.GID {
		return ErrConflict
	}
	f, e := openInstalledBinary(p)
	if e != nil {
		return e
	}
	uid, _ := parseUID(p.Input.UID)
	gid, _ := parseUID(p.Input.GID)
	cmd := exec.CommandContext(ctx, p.BinaryPath, "local-enrollment-check", "--local-directory", p.StateDirectory, "--local-user", p.Input.UID)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: false}}
	out := boundedOutput{limit: maxLocalCompletionBytes}
	discard := boundedOutput{limit: maxLocalCompletionBytes}
	cmd.Stdout = &out
	cmd.Stderr = &discard
	runErr := cmd.Run()
	closeErr := f.Close()
	if closeErr != nil {
		return ErrPersistence
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runErr != nil {
		return ErrState
	}
	if n.lease.guard() != nil {
		return ErrPermission
	}
	return decodeEnrollmentCompletion(out.b.Bytes())
}

// Only public UID/GID/capability fields are examined; no process environment is read.
func verifyServiceProcess(p Plan, pid uint32) error {
	if pid == 0 {
		return ErrState
	}
	f, e := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	if e != nil {
		return ErrBusy
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	ce := f.Close()
	if e != nil || ce != nil || len(b) > 65536 {
		return ErrState
	}
	want := map[string]string{"Uid:": p.Input.UID, "Gid:": p.Input.GID}
	seen := map[string]bool{}
	capOK, nnpOK := false, false
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if v, ok := want[fields[0]]; ok {
			if seen[fields[0]] || len(fields) != 5 {
				return ErrState
			}
			seen[fields[0]] = true
			for _, n := range fields[1:] {
				if n != v {
					return ErrPermission
				}
			}
		}
		if fields[0] == "CapEff:" {
			if len(fields) != 2 || fields[1] != "0000000000000000" {
				return ErrPermission
			}
			capOK = true
		}
		if fields[0] == "NoNewPrivs:" {
			if len(fields) != 2 || fields[1] != "1" {
				return ErrPermission
			}
			nnpOK = true
		}
	}
	if !seen["Uid:"] || !seen["Gid:"] || !capOK || !nnpOK {
		return ErrPermission
	}
	return nil
}
