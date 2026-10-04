// Package launchctlprint 只解析有界 launchctl print 输出，不授予服务身份或设备信任。
package launchctlprint

import (
	"bytes"
	"errors"
	"strings"
)

var ErrMalformed = errors.New("launchctl job output malformed")

type Job struct {
	Fields    map[string]string
	Arguments []string
}

// Decode 校验完整固定 system scope，仅收集唯一的顶层字段。
// 嵌套 resource/jetsam 等块的同名字段不进入顶层身份；调用方仍须核验全部期望值。
func Decode(raw []byte, label string) (Job, error) {
	if len(raw) > 256<<10 || bytes.IndexByte(raw, 0) >= 0 || label == "" || len(label) > 256 || strings.ContainsAny(label, "\r\n{}") {
		return Job{}, ErrMalformed
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "system/"+label+" = {" {
		return Job{}, ErrMalformed
	}
	job := Job{Fields: map[string]string{}}
	depth, argsSeen, inArgs := 1, false, false
	for index, rawLine := range lines[1:] {
		line := strings.TrimSpace(rawLine)
		if len(rawLine) > 4096 || depth < 1 {
			return Job{}, ErrMalformed
		}
		if line == "}" {
			if inArgs {
				if depth != 2 {
					return Job{}, ErrMalformed
				}
				inArgs = false
			}
			depth--
			if depth == 0 && index != len(lines)-2 {
				return Job{}, ErrMalformed
			}
			continue
		}
		if inArgs {
			if depth != 2 || len(job.Arguments) >= 32 || strings.ContainsAny(line, "{}") {
				return Job{}, ErrMalformed
			}
			job.Arguments = append(job.Arguments, line)
			continue
		}
		if strings.HasSuffix(line, " = {") {
			name := strings.TrimSuffix(line, " = {")
			if name == "" || strings.ContainsAny(name, "{}") || depth >= 16 {
				return Job{}, ErrMalformed
			}
			if depth == 1 && name == "arguments" {
				if argsSeen {
					return Job{}, ErrMalformed
				}
				argsSeen, inArgs = true, true
				job.Arguments = []string{}
			}
			depth++
			continue
		}
		if strings.ContainsAny(line, "{}") {
			return Job{}, ErrMalformed
		}
		if depth != 1 {
			continue
		}
		for _, key := range []string{"path", "program", "username", "type", "pid", "state"} {
			if strings.HasPrefix(line, key+" = ") {
				if _, exists := job.Fields[key]; exists {
					return Job{}, ErrMalformed
				}
				job.Fields[key] = strings.TrimPrefix(line, key+" = ")
			}
		}
	}
	if depth != 0 || inArgs || !argsSeen {
		return Job{}, ErrMalformed
	}
	return job, nil
}
