package launchctlprint

import (
	"strings"
	"testing"
)

const testLabel = "org.harmonia-vault.user.501"

func nestedJob() string {
	return "system/" + testLabel + " = {\npath = /synthetic.plist\nprogram = /synthetic\nusername = synthetic\ntype = LaunchDaemon\npid = 431\nstate = running\narguments = {\n/synthetic\ndaemon\n}\nresource coalition = {\ntype = resource\nstate = active\npid = 999\n}\njetsam coalition = {\ntype = jetsam\nstate = active\n}\n}"
}

func TestActualNestedShapeKeepsOnlyTopLevel(t *testing.T) {
	job, err := Decode([]byte(nestedJob()), testLabel)
	if err != nil || job.Fields["type"] != "LaunchDaemon" || job.Fields["state"] != "running" || job.Fields["pid"] != "431" || strings.Join(job.Arguments, "\x00") != "/synthetic\x00daemon" {
		t.Fatal("合法嵌套结构污染顶层", err)
	}
}

func TestDuplicateTopLevelRemainsRejected(t *testing.T) {
	for _, key := range []string{"path", "program", "username", "type", "pid", "state"} {
		body := strings.Replace(nestedJob(), "\narguments = {", "\n"+key+" = duplicate\narguments = {", 1)
		if _, err := Decode([]byte(body), testLabel); err == nil {
			t.Fatal("顶层重复字段被接受", key)
		}
	}
}

func TestScopeBracesAndArgumentsRemainStrict(t *testing.T) {
	for _, body := range []string{
		strings.TrimSuffix(nestedJob(), "}"), nestedJob() + "\n}", nestedJob() + "\nstate = running",
		strings.Replace(nestedJob(), " = {", ".other = {", 1),
		strings.Replace(nestedJob(), "resource coalition = {", "resource coalition = }", 1),
		strings.Replace(nestedJob(), "resource coalition = {", "arguments = {", 1),
		strings.Replace(nestedJob(), "/synthetic\ndaemon", "/synthetic\narguments = {", 1),
	} {
		if _, err := Decode([]byte(body), testLabel); err == nil {
			t.Fatal("损坏scope/括号/参数块被接受")
		}
	}
}
