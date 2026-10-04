package windowsaccount

import "testing"

func TestRightsDeltaNeverRemovesExistingOrDenyRights(t *testing.T) {
	before := []string{"SeBatchLogonRight", DenyServiceLogonRight}
	if add, e := rightShouldBeAdded(before, false, false); e == nil || add {
		t.Fatal("直接Deny被绕过")
	}
	if add, e := rightShouldBeAdded(nil, false, true); e == nil || add {
		t.Fatal("组Deny被绕过")
	}
	if add, e := rightShouldBeAdded(nil, true, false); e != nil || add {
		t.Fatal("已有组allow时仍新增直接权限")
	}
	if add, e := rightShouldBeAdded([]string{ServiceLogonRight}, false, false); e != nil || add {
		t.Fatal("已有直接权限仍被记为新增")
	}
	if add, e := rightShouldBeAdded([]string{"SeBatchLogonRight"}, false, false); e != nil || !add {
		t.Fatal("缺权限的精确新增计划错误")
	}
	if !rightAdditionMatches(before, []string{ServiceLogonRight, DenyServiceLogonRight, "SeBatchLogonRight"}) || rightAdditionMatches(before, []string{ServiceLogonRight}) {
		t.Fatal("新增差量顺带丢失旧权限")
	}
	if !rightRemovalMatches([]string{ServiceLogonRight, DenyServiceLogonRight, "SeBatchLogonRight"}, before) || rightRemovalMatches([]string{ServiceLogonRight, DenyServiceLogonRight}, nil) {
		t.Fatal("撤销差量顺带删除Deny")
	}
}

func TestStopAfterUnknownStartKeepsIncompleteInstallClosed(t *testing.T) {
	for _, pending := range []string{"", "start-service", "enable-automatic", "disable-and-drain"} {
		if !mayStopReceipt(Receipt{Stage: "installed-disabled", Pending: pending}) {
			t.Fatalf("cannot safely stop after %s", pending)
		}
	}
	for _, receipt := range []Receipt{{Stage: "files-ready"}, {Stage: "installed-disabled", Pending: "grant-service-logon"}, {Stage: "service-removed"}} {
		if mayStopReceipt(receipt) {
			t.Fatal("incomplete or removed installation accepted")
		}
	}
}
