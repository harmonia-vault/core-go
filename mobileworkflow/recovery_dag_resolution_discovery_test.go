package mobileworkflow

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

func discoveryForbiddenNetwork(hits *atomic.Int32) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		hits.Add(1)
		return nil, errors.New("discovery must not access network")
	}
	return &http.Client{Transport: tr}
}

func TestDAGResolutionDiscoveryColdClosedAndSealedSource(t *testing.T) {
	c, w, _, p, slot := resolutionFixture(t)
	var network atomic.Int32
	w.http = discoveryForbiddenNetwork(&network)
	before := slot.read()
	discovery, e := w.RecoveryDAGResolutionDiscoveryInfo()
	if e != nil || discovery.State != "supported-original" || discovery.TrustedDevice {
		t.Fatal("valid original discovery", e)
	}
	info, e := w.RecoveryDAGResolutionInfo()
	if e != nil || info.OperationID != discovery.OperationID || info.TargetHash != discovery.TargetHash {
		t.Fatal("exact original target", e)
	}
	if !bytes.Equal(before, slot.read()) || network.Load() != 0 {
		t.Fatal("metadata modified native state or network")
	}
	candidate := resolutionClosedCandidate(t, w, resolutionPlanFixture(t, w, p))
	if e = w.saveDAGCandidateLocked(candidate); e != nil {
		t.Fatal(e)
	}
	w.Close()
	c.ProtectedState = slot.read()
	c.HTTPClient = discoveryForbiddenNetwork(&network)
	cold, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	before = slot.read()
	discovery, e = cold.RecoveryDAGResolutionDiscoveryInfo()
	if e != nil || discovery.State != "closed" || discovery.OperationID != info.OperationID || discovery.TargetHash != info.TargetHash {
		t.Fatal("durable cold closed unreachable", e)
	}
	exact, e := cold.RecoveryDAGResolutionInfo()
	if e != nil || exact.OperationID != discovery.OperationID || exact.TargetHash != discovery.TargetHash {
		t.Fatal("cold Info changed target", e)
	}
	if !bytes.Equal(before, slot.read()) || network.Load() != 0 {
		t.Fatal("cold discovery wrote or used network")
	}
	// 即使 RAM 合法，外部原生状态已变也不能给closed或none。
	slot.mu.Lock()
	slot.packet = append(slot.packet, 1)
	slot.mu.Unlock()
	if out, e := cold.RecoveryDAGResolutionDiscoveryInfo(); e == nil || out.State != "" {
		t.Fatal("stale protected capture returned metadata")
	}
}

func TestDAGResolutionDiscoveryNoneUnsupportedAndMismatch(t *testing.T) {
	c := testConfig(t)
	slot := &dagNativeSlot{}
	var network atomic.Int32
	c.SaveProtectedStateCAS = slot.cas
	c.CheckProtectedState = slot.check
	c.HTTPClient = discoveryForbiddenNetwork(&network)
	w, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	out, e := w.RecoveryDAGResolutionDiscoveryInfo()
	if e != nil || out.State != "none" || out.OperationID != "" || out.TargetHash != "" {
		t.Fatal("fresh none", e)
	}
	w.Close()
	_, recovered, recoveredJournal, preparation, packet, _ := b3MobileFixture(t)
	defer recovered.Close()
	recovered.http = c.HTTPClient
	recoveredStore, e := recovered.newDAGPreparationStore()
	if e != nil {
		t.Fatal(e)
	}
	if e = recoveredStore.SaveRecoveredPreparation(b3Intent(preparation)); e != nil {
		t.Fatal(e)
	}
	if e = recoveredStore.SaveRecoveredPreparation(preparation); e != nil {
		t.Fatal(e)
	}
	if e = recoveredJournal.Save(packet); e != nil {
		t.Fatal(e)
	}
	if packet.Recovered == nil || packet.Transition != nil {
		t.Fatal("negative requires genuine recovered packet")
	}
	out, e = recovered.RecoveryDAGResolutionDiscoveryInfo()
	if e != nil || out.State != "unsupported" || out.OperationID != "" || out.TargetHash != "" {
		t.Fatal("recovered journal generalized", e)
	}
	_, prepared, _, original, _ := b2MobileFixture(t)
	defer prepared.Close()
	prepared.http = c.HTTPClient
	store, e := prepared.newDAGPreparationStore()
	if e != nil {
		t.Fatal(e)
	}
	if e = store.SaveTransitionPreparation(b2Intent(b2Preparation(t, original))); e != nil {
		t.Fatal(e)
	}
	out, e = prepared.RecoveryDAGResolutionDiscoveryInfo()
	if e != nil || out.State != "unsupported" || out.OperationID != "" || out.TargetHash != "" {
		t.Fatal("intent generalized", e)
	}
	// 对真实closed candidate破坏账号代际，必须拒绝，不能投影none。
	_, base, _, p, _ := resolutionFixture(t)
	defer base.Close()
	base.http = c.HTTPClient
	invalid := resolutionClosedCandidate(t, base, resolutionPlanFixture(t, base, p))
	invalid.RecoveryDAGResolution.AccountGeneration++
	base.state = invalid
	if out, e = base.RecoveryDAGResolutionDiscoveryInfo(); e == nil || out.State != "" {
		t.Fatal("binding mismatch disguised as none")
	}
	if network.Load() != 0 {
		t.Fatal("discovery accessed network")
	}
}
