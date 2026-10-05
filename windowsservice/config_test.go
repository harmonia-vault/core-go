package windowsservice

import (
	"encoding/json"
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{Schema: Schema, TargetSID: "S-1-5-21-111-222-333-10001", SyncServiceSID: "S-1-5-80-1-2-3-4-5", BrokerServiceSID: "S-1-5-80-6-7-8-9-10", Executable: `C:\Program Files\Harmonia\profile.exe`, SyncExecutable: `C:\Program Files\Harmonia\sync.exe`, ConfigurationFile: `C:\ProgramData\Harmonia\profile.json`}
}
func TestConfigIdentityAndPaths(t *testing.T) {
	c := testConfig()
	b, _ := json.Marshal(c)
	if _, e := DecodeConfig(b); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.TargetSID = "S-1-5-18" }, func(c *Config) { c.SyncServiceSID = c.BrokerServiceSID }, func(c *Config) { c.BrokerServiceSID = "S-1-5-80-01-2-3-4-5" }, func(c *Config) { c.Executable = `\\server\profile.exe` }, func(c *Config) { c.ConfigurationFile = `C:\bad\..\profile.json` }, func(c *Config) { c.ConfigurationFile = `C:\path\profile.json:stream` }, func(c *Config) { c.ConfigurationFile = `C:\path \profile.json` }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	for _, bad := range []string{string(b) + "{}", strings.Replace(string(b), `"schema":`, `"schema":"wrong","schema":`, 1), strings.Replace(string(b), `"schema":`, `"unknown":"x","schema":`, 1)} {
		if _, e := DecodeConfig([]byte(bad)); e == nil {
			t.Fatal("accepted ambiguous config")
		}
	}
}
func TestTaskMutation(t *testing.T) {
	c := testConfig()
	doc, e := c.TaskXML()
	if e != nil || c.ValidateTask([]byte(doc)) != nil {
		t.Fatalf("template: %v", e)
	}
	for _, bad := range []string{strings.Replace(doc, "S4U", "InteractiveToken", 1), strings.Replace(doc, c.TargetSID, "S-1-5-21-111-222-333-10002", 1), strings.Replace(doc, "LeastPrivilege", "HighestAvailable", 1), strings.Replace(doc, "</Actions>", "<ComHandler><ClassId>x</ClassId></ComHandler></Actions>", 1), strings.Replace(doc, "token --config", "token --other", 1), strings.Replace(doc, "PT30S", "PT1H", 1)} {
		if c.ValidateTask([]byte(bad)) == nil {
			t.Fatal("accepted mutated task")
		}
	}
}
