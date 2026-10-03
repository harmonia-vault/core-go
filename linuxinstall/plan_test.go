package linuxinstall

import (
	"context"
	"strings"
	"testing"
)

func syntheticPlan(t *testing.T) Plan {
	t.Helper()
	p, err := NewPlan(Input{UserName: "harmonia_lab", UID: "10001", GID: "10001", BinarySource: "/opt/harmonia-test/native-cli", BinarySHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSingleUIDPlanAndGuard(t *testing.T) {
	p := syntheticPlan(t)
	u, err := p.Unit()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"User=harmonia_lab\n", "WantedBy=multi-user.target\n", "RequiresMountsFor=/var/lib/harmonia/10001\n", "ConditionPathExists=!/var/lib/harmonia-installer/10001.uninstalling\n", "CapabilityBoundingSet=\n", "ReadWritePaths=\"/var/lib/harmonia/10001\"\n"} {
		if !strings.Contains(string(u.Content), s) {
			t.Fatalf("missing restriction %q", s)
		}
	}
	if strings.Contains(string(u.Content), "/home/") || strings.Contains(string(u.Content), p.Input.BinarySource) || strings.Contains(string(u.Content), "[Timer]") {
		t.Fatal("unit acquired an unintended source/home/timer dependency")
	}
	if p.UnitName != "harmonia-user-10001.service" || p.StateDirectory != "/var/lib/harmonia/10001" {
		t.Fatal("UID scope changed")
	}
}
func TestPlanRejectsIdentityAndPathInjection(t *testing.T) {
	base := syntheticPlan(t).Input
	cases := []struct {
		name   string
		change func(*Input)
	}{
		{"rootuid", func(i *Input) { i.UID = "0" }}, {"ambiguousuid", func(i *Input) { i.UID = "010001" }}, {"uidnewline", func(i *Input) { i.UID = "10001\n" }}, {"rootname", func(i *Input) { i.UserName = "root" }}, {"unitinjection", func(i *Input) { i.UserName = "lab\nExecStart=/bin/sh" }}, {"overflow", func(i *Input) { i.UID = "4294967296" }}, {"gidroot", func(i *Input) { i.GID = "0" }}, {"relative", func(i *Input) { i.BinarySource = "native-cli" }}, {"parentpath", func(i *Input) { i.BinarySource = "/opt/../bin/cli" }}, {"missingdigest", func(i *Input) { i.BinarySHA256 = "" }}, {"caunbound", func(i *Input) { i.CASource = "/opt/ca.pem" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.change(&in)
			if _, err := NewPlan(in); err != ErrPlan {
				t.Fatalf("accepted invalid input: %v", err)
			}
		})
	}
	p := syntheticPlan(t)
	p.StateDirectory = "/var/lib/harmonia/10002"
	if _, err := p.Unit(); err != ErrPlan {
		t.Fatal("tampered fixed target accepted")
	}
}
func TestMissingSharedDependenciesCannotBecomeSuccess(t *testing.T) {
	p := syntheticPlan(t)
	d := ClosedDependencies{}
	if d.CheckEnrollment(context.Background(), p) != ErrUnsupported || d.LogoutOffline(context.Background(), p) != ErrUnsupported {
		t.Fatal("unimplemented dependency falsely succeeded")
	}
}
