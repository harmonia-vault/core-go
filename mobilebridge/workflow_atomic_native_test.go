package mobilebridge

import (
	"bytes"
	"errors"
	"testing"
)

type typedAtomicNativeFixture struct {
	atomicSealedFixture
	checks, cas int
	failCheck   int
}

func (s *typedAtomicNativeFixture) CheckSealed(expected []byte) error {
	s.checks++
	if s.checks == s.failCheck {
		return errors.New("synthetic check rejection")
	}
	return s.atomicSealedFixture.CheckSealed(expected)
}
func (s *typedAtomicNativeFixture) CompareAndSwapSealed(expected, next []byte) error {
	s.cas++
	return s.atomicSealedFixture.CompareAndSwapSealed(expected, next)
}
func TestTypedAtomicNativeOpenPreservesCheckAndCAS(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	slot := &typedAtomicNativeFixture{}
	v, err := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-native-slot", nil, nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if slot.checks != 2 {
		t.Fatal("opener did not check captured state at both boundaries")
	}
	plain, err := v.workflow.ExportProtectedState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if err = v.saveCAS(v.protectedSHA256, plain); err != nil {
		t.Fatal(err)
	}
	if slot.cas != 1 || len(slot.read()) == 0 {
		t.Fatal("typed provider lost CAS callback")
	}
	current := slot.read()
	if err = v.checkProtected(v.protectedSHA256); err != nil {
		t.Fatal(err)
	}
	slot.packet = append(bytes.Clone(current), 1)
	if err = v.checkProtected(v.protectedSHA256); err == nil {
		t.Fatal("stale owner stayed live")
	}
	if err = v.saveCAS(v.protectedSHA256, plain); err == nil || slot.cas != 1 {
		t.Fatal("failed Check permitted later CAS")
	}
}
func TestTypedAtomicNativeOpenRejectsFailedBoundary(t *testing.T) {
	for _, boundary := range []int{1, 2} {
		d, err := NewDevice()
		if err != nil {
			t.Fatal(err)
		}
		slot := &typedAtomicNativeFixture{failCheck: boundary}
		v, err := d.OpenAtomicWorkflow("https://synthetic.example.invalid", "synthetic-native-slot", nil, nil, slot)
		if err == nil || v != nil || len(slot.read()) != 0 {
			t.Fatal("failed captured boundary opened or wrote")
		}
		d.Close()
	}
}
