package mobilebridge

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

type atomicSealedFixture struct {
	mu     sync.Mutex
	packet []byte
}

func (s *atomicSealedFixture) SaveSealed(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packet = bytes.Clone(p)
	return nil
}
func (s *atomicSealedFixture) CompareAndSwapSealed(old, next []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.packet == nil) != (old == nil) || !bytes.Equal(s.packet, old) {
		return errors.New("synthetic whole-state CAS conflict")
	}
	s.packet = bytes.Clone(next)
	return nil
}
func (s *atomicSealedFixture) CheckSealed(expected []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.packet == nil) != (expected == nil) || !bytes.Equal(s.packet, expected) {
		return errors.New("synthetic stale native owner")
	}
	return nil
}
func (s *atomicSealedFixture) read() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.packet)
}
func TestNativeSealedCASRejectsIndependentWorkflowAfterLogout(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	slot := &atomicSealedFixture{}
	first, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", nil, nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	plain, err := first.workflow.ExportProtectedState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if err = first.saveCAS(first.protectedSHA256, plain); err != nil {
		t.Fatal(err)
	}
	second, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", slot.read(), nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	observer, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", slot.read(), nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if err = first.checkProtected(first.protectedSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err = second.Execute(`{"version":1,"operation":"logout","endpoint":"https://synthetic.example.invalid"}`); err != nil {
		t.Fatal(err)
	}
	closed := slot.read()
	if err = observer.checkProtected(observer.protectedSHA256); err == nil {
		t.Fatal("native owner stayed live after independent logout")
	}
	if err = first.saveCAS(first.protectedSHA256, plain); err == nil {
		t.Fatal("stale protected owner replaced logout")
	}
	if !bytes.Equal(slot.read(), closed) || !first.saveFailed.Load() {
		t.Fatal("CAS failure lost tombstone or left owner usable")
	}
	reopened, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", closed, nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.binding.AccountClosed {
		t.Fatal("durable closed account was revived")
	}
}
func TestNativeDAGCASUnavailableForSaveOnlyProvider(t *testing.T) {
	d, err := NewDevice()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	slot := &memorySealed{}
	v, err := d.OpenWorkflow("https://synthetic.example.invalid", "synthetic-state", nil, nil, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	plain, err := v.workflow.ExportProtectedState()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if err = v.saveCAS(v.protectedSHA256, plain); err == nil {
		t.Fatal("Save-only provider pretended atomic CAS")
	}
	if len(slot.packet) != 0 {
		t.Fatal("unsupported CAS fell back to ordinary save")
	}
}
