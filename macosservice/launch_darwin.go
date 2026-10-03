//go:build darwin

package macosservice

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// 官方print-disabled只有domain接口；有界RAM仅投影固定label，不输出/保存其他配置。
type boundedCommand struct {
	stdout, stderr []byte
	exit           int
}

func commandBounded(ctx context.Context, limit int, p string, args ...string) (boundedCommand, error) {
	if limit <= 0 || limit > 256<<10 {
		return boundedCommand{}, ErrUnknown
	}
	c := safeCommand(ctx, p, args...)
	stderr := boundedCapture{limit: limit}
	c.Stderr = &stderr
	pipe, e := c.StdoutPipe()
	if e != nil {
		return boundedCommand{}, ErrUnknown
	}
	if e = c.Start(); e != nil {
		return boundedCommand{}, ErrUnknown
	}
	out, re := io.ReadAll(io.LimitReader(pipe, int64(limit)+1))
	ce := pipe.Close()
	we := c.Wait()
	if re != nil || ce != nil || len(out) > limit || stderr.exceeded || ctx.Err() != nil {
		return boundedCommand{}, ErrUnknown
	}
	exit := 0
	if we != nil {
		type exited interface{ ExitCode() int }
		x, ok := we.(exited)
		if !ok {
			return boundedCommand{}, ErrUnknown
		}
		exit = x.ExitCode()
	}
	return boundedCommand{stdout: out, stderr: stderr.b.Bytes(), exit: exit}, nil
}

// 达到界限后继续丢弃，避免子进程堵管；只保存有界进程内字节。
type boundedCapture struct {
	b        bytes.Buffer
	limit    int
	exceeded bool
}

func (d *boundedCapture) Write(b []byte) (int, error) {
	remaining := d.limit - d.b.Len()
	kept := len(b)
	if kept > remaining {
		kept = remaining
		d.exceeded = true
	}
	if kept > 0 {
		_, _ = d.b.Write(b[:kept])
	}
	return len(b), nil
}
func observedCommand(result boundedCommand, l layout, t Target) (jobSnapshot, error) {
	if bytes.IndexByte(result.stdout, 0) >= 0 || bytes.IndexByte(result.stderr, 0) >= 0 {
		return jobSnapshot{}, ErrUnknown
	}
	if result.exit == 113 {
		if len(bytes.TrimSpace(result.stdout)) != 0 {
			return jobSnapshot{}, ErrUnknown
		}
		diagnostic := strings.TrimSpace(string(result.stderr))
		want := `Could not find service "` + l.Label + `" in domain for system`
		if diagnostic == want || diagnostic == "Bad request.\n"+want {
			return jobSnapshot{State: absent}, nil
		}
		return jobSnapshot{}, ErrUnknown
	}
	if result.exit != 0 || len(bytes.TrimSpace(result.stderr)) != 0 {
		return jobSnapshot{}, ErrUnknown
	}
	return observedJob(result.stdout, 0, l, t)
}

var disabledLine = regexp.MustCompile(`^"([^"\\]+)"\s+=>\s+(true|false)$`)

func disabledStatus(b []byte, exit int, label string) (bool, bool, error) {
	if exit != 0 || len(b) > 256<<10 || bytes.IndexByte(b, 0) >= 0 {
		return false, false, ErrUnknown
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "disabled services = {" || strings.TrimSpace(lines[len(lines)-1]) != "}" {
		return false, false, ErrUnknown
	}
	seen := map[string]bool{}
	present, value := false, false
	for _, raw := range lines[1 : len(lines)-1] {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		m := disabledLine.FindStringSubmatch(line)
		if len(m) != 3 || seen[m[1]] {
			return false, false, ErrUnknown
		}
		seen[m[1]] = true
		if m[1] == label {
			present, value = true, m[2] == "true"
		}
	}
	return present, value, nil
}
func (darwinRunner) disabled(ctx context.Context, l layout) (bool, bool, error) {
	result, e := commandBounded(ctx, 256<<10, "/bin/launchctl", "print-disabled", "system")
	if e != nil {
		return false, false, e
	}
	if len(bytes.TrimSpace(result.stderr)) != 0 {
		return false, false, ErrUnknown
	}
	return disabledStatus(result.stdout, result.exit, l.Label)
}
func (darwinRunner) setDisabled(ctx context.Context, l layout, value bool) error {
	action := "enable"
	if value {
		action = "disable"
	}
	if safeCommand(ctx, "/bin/launchctl", action, "system/"+l.Label).Run() != nil {
		return ErrUnknown
	}
	return nil
}
func observedJob(b []byte, exit int, l layout, t Target) (jobSnapshot, error) {
	state := launchState(b, exit, l, t)
	if state == unknown {
		return jobSnapshot{}, ErrUnknown
	}
	if state == absent {
		return jobSnapshot{State: absent}, nil
	}
	var pid int
	seenPID, seenState := false, false
	stable := false
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "pid = ") {
			if seenPID {
				return jobSnapshot{}, ErrUnknown
			}
			seenPID = true
			text := strings.TrimPrefix(line, "pid = ")
			v, e := strconv.Atoi(text)
			if e != nil || v < 2 || strconv.Itoa(v) != text {
				return jobSnapshot{}, ErrUnknown
			}
			pid = v
		}
		if strings.HasPrefix(line, "state = ") {
			if seenState {
				return jobSnapshot{}, ErrUnknown
			}
			seenState = true
			switch strings.TrimPrefix(line, "state = ") {
			case "running":
				stable = true
			case "not running", "waiting", "exited":
				stable = true
			default:
				return jobSnapshot{}, ErrUnknown
			}
		}
	}
	if !seenState {
		return jobSnapshot{}, ErrUnknown
	}
	if seenPID {
		return jobSnapshot{State: matching, PID: pid}, nil
	}
	if !stable {
		return jobSnapshot{}, ErrUnknown
	}
	return jobSnapshot{State: matching, StableNoPID: true}, nil
}
func (darwinRunner) observeJob(ctx context.Context, l layout, t Target) (jobSnapshot, error) {
	result, e := commandBounded(ctx, 64<<10, "/bin/launchctl", "print", "system/"+l.Label)
	if e != nil {
		return jobSnapshot{}, e
	}
	return observedCommand(result, l, t)
}
