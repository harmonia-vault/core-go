package windowsaccount

import (
	"errors"
	"slices"
	"testing"
)

type inventoryFixture struct {
	first, second       []registryServiceRecord
	observed            map[string]serviceObservation
	failures            map[string]error
	sids                map[string]string
	readCalls, failRead int
}

func (f *inventoryFixture) Registry() ([]registryServiceRecord, error) {
	f.readCalls++
	if f.readCalls == f.failRead {
		return nil, errors.New("synthetic registry read refused")
	}
	if f.readCalls == 1 {
		return slices.Clone(f.first), nil
	}
	return slices.Clone(f.second), nil
}
func (f *inventoryFixture) Service(name string) (serviceObservation, error) {
	if e := f.failures[name]; e != nil {
		return serviceObservation{}, e
	}
	v, ok := f.observed[name]
	if !ok {
		return serviceObservation{}, errServiceNotPresent
	}
	return v, nil
}
func (f *inventoryFixture) Resolve(name string) (string, error) {
	if sid, ok := f.sids[name]; ok {
		return sid, nil
	}
	return "", errors.New("synthetic unknown account")
}
func inventoryBase() *inventoryFixture {
	entries := []registryServiceRecord{{Name: "driver", Type: 1, HasType: true, WriteStamp: 1}, {Name: "metadata", WriteStamp: 2}, {Name: "visible", Type: 0x10, HasType: true, WriteStamp: 3}}
	return &inventoryFixture{first: entries, second: slices.Clone(entries), observed: map[string]serviceObservation{"driver": {Type: 1, State: 4}, "visible": {Type: 0x10, Account: "LocalSystem", State: 4, ProcessID: 12}}, failures: map[string]error{}, sids: map[string]string{"S-1-5-18": "S-1-5-18", "synthetic-other": "S-1-5-21-111-222-333-1002", "synthetic-target": "S-1-5-21-111-222-333-1001"}}
}

// 模拟原EnumServicesStatusEx会隐藏的拒绝查询项，以及跨完整快照的故障。
// 只有Complete才可作为MayRemove前置；未知返回的零Count永远不能成为撤销许可。
func TestServiceUserInventoryNeverTurnsUnknownIntoRemovalPermission(t *testing.T) {
	target := "S-1-5-21-111-222-333-1001"
	cases := map[string]func(*inventoryFixture){
		"empty-is-not-complete":         func(f *inventoryFixture) { f.first = nil; f.second = nil },
		"root-last-write-changed":       func(f *inventoryFixture) { f.second[0].RootWriteStamp++ },
		"first-registry-access-denied":  func(f *inventoryFixture) { f.failRead = 1 },
		"second-registry-access-denied": func(f *inventoryFixture) { f.failRead = 2 },
		"hidden-query-status-denied": func(f *inventoryFixture) {
			f.first = append(f.first, registryServiceRecord{Name: "hidden", Type: 0x10, HasType: true, Account: "synthetic-target", HasAccount: true})
			f.second = slices.Clone(f.first)
			f.failures["hidden"] = errors.New("access denied")
		},
		"metadata-unknown-is-not-absent":  func(f *inventoryFixture) { f.failures["metadata"] = errors.New("marked for deletion") },
		"registry-service-missing-in-scm": func(f *inventoryFixture) { delete(f.observed, "visible") },
		"type-mismatch":                   func(f *inventoryFixture) { v := f.observed["visible"]; v.Type = 0x20; f.observed["visible"] = v },
		"account-sid-mismatch": func(f *inventoryFixture) {
			v := f.observed["visible"]
			v.Account = "synthetic-target"
			f.observed["visible"] = v
		},
		"account-unknown": func(f *inventoryFixture) {
			v := f.observed["visible"]
			v.Account = "unknown-local-account"
			f.observed["visible"] = v
		},
		"unknown-type": func(f *inventoryFixture) {
			f.first[2].Type = 0x210
			f.second = slices.Clone(f.first)
			v := f.observed["visible"]
			v.Type = 0x210
			f.observed["visible"] = v
		},
		"per-user-context-unproven": func(f *inventoryFixture) {
			f.first[2].Type = 0x50
			f.second = slices.Clone(f.first)
			v := f.observed["visible"]
			v.Type = 0x50
			f.observed["visible"] = v
		},
		"invalid-state": func(f *inventoryFixture) { v := f.observed["visible"]; v.State = 0; f.observed["visible"] = v },
		"key-added": func(f *inventoryFixture) {
			f.second = append(f.second, registryServiceRecord{Name: "new-account-service", Type: 0x10, HasType: true})
		},
		"key-deleted":        func(f *inventoryFixture) { f.second = f.second[:2] },
		"account-changed":    func(f *inventoryFixture) { f.second[2].Account = "synthetic-target"; f.second[2].HasAccount = true },
		"type-changed":       func(f *inventoryFixture) { f.second[2].Type = 0x20 },
		"last-write-changed": func(f *inventoryFixture) { f.second[2].WriteStamp++ },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := inventoryBase()
			edit(f)
			proof, e := inspectServiceUsers(target, f)
			receipt := RightReceipt{TargetSID: target, AddedByInstall: true}
			mayRemove := proof.Complete && receipt.MayRemove(target, true, proof.Count, true)
			if e == nil || proof.Complete || mayRemove {
				t.Fatal("unknown inventory permitted account-right removal")
			}
		})
	}
	t.Run("verified-empty-allows-owned-delta-only", func(t *testing.T) {
		proof, e := inspectServiceUsers(target, inventoryBase())
		if e != nil || !proof.Complete || proof.Count != 0 {
			t.Fatal("complete empty inventory rejected")
		}
		r := RightReceipt{TargetSID: target, AddedByInstall: true}
		if !r.MayRemove(target, true, proof.Count, true) {
			t.Fatal("exact owned delta rejected")
		}
		r.DirectBefore = true
		if r.MayRemove(target, true, proof.Count, true) {
			t.Fatal("existing right became removable")
		}
	})
	t.Run("another-user-of-account-retains-right", func(t *testing.T) {
		f := inventoryBase()
		f.first[2].Account = "synthetic-target"
		f.first[2].HasAccount = true
		f.second = slices.Clone(f.first)
		v := f.observed["visible"]
		v.Account = "synthetic-target"
		f.observed["visible"] = v
		proof, e := inspectServiceUsers(target, f)
		r := RightReceipt{TargetSID: target, AddedByInstall: true}
		if e != nil || !proof.Complete || proof.Count != 1 || r.MayRemove(target, true, proof.Count, true) {
			t.Fatal("another registered service lost its account right")
		}
	})
}
