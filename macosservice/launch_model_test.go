package macosservice

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

func (f *fakeFS) prepareCreation(p, parent string, b []byte, uid, gid, mode uint32, dir bool) (creation, error) {
	f.prepareCalls++
	if p == f.failWrite || f.prepareCalls == f.failPrepareAt {
		return creation{}, ErrUnknown
	}
	pn, e := f.inspect(parent)
	if e != nil {
		return creation{}, e
	}
	fn, e := f.inspect(filepath.Dir(p))
	if e != nil {
		return creation{}, e
	}
	stage := fmt.Sprintf(".harmonia.501.stage.%032x", f.next+1)
	// model不同UID通过实际最终路径推导，不复用某账号状态。
	if strings.Contains(p, "502") {
		stage = fmt.Sprintf(".harmonia.502.stage.%032x", f.next+1)
	}
	k := regular
	if dir {
		k = directory
	}
	n := f.add(parent+"/"+stage, k, uid, gid, mode, b)
	h := ""
	if !dir {
		h = digest(b)
	}
	return creation{Stage: stage, Parent: pn, FinalParent: fn, Node: n, Hash: h}, nil
}
func (f *fakeFS) commitCreation(p, parent string, x creation) error {
	f.commitCalls++
	if f.commitCalls == f.failCommitAt && !f.failCommitAfter {
		return ErrUnknown
	}
	pn, e := f.inspect(parent)
	if e != nil || !equalNode(pn, x.Parent) {
		return ErrUnknown
	}
	fn, e := f.inspect(filepath.Dir(p))
	if e != nil || !equalNode(fn, x.FinalParent) {
		return ErrUnknown
	}
	stage := parent + "/" + x.Stage
	o, hasFinal := f.objects[p]
	s, hasStage := f.objects[stage]
	if hasFinal {
		if hasStage || !equalNode(o.n, x.Node) || (o.n.Kind == regular && digest(o.data) != x.Hash) {
			return ErrUnknown
		}
		return nil
	}
	if !hasStage || !equalNode(s.n, x.Node) || (s.n.Kind == regular && digest(s.data) != x.Hash) {
		return ErrUnknown
	}
	delete(f.objects, stage)
	f.objects[p] = s
	if f.onCommit != nil {
		f.onCommit(p)
	}
	if f.commitCalls == f.failCommitAt && f.failCommitAfter {
		return ErrUnknown
	}
	return nil
}
func (f *fakeFS) childrenCreated(p string, n node) ([]entry, error) {
	current, e := f.inspect(p)
	if e != nil || !equalNode(current, n) {
		return nil, ErrUnknown
	}
	return f.children(p)
}
func (r *fakeRunner) disabled(_ context.Context, l layout) (bool, bool, error) {
	if r.gateQueryError {
		return false, false, ErrUnknown
	}
	v, ok := r.disabledValues[l.Label]
	return ok, v, nil
}
func (r *fakeRunner) setDisabled(_ context.Context, l layout, v bool) error {
	if r.gateError {
		return ErrUnknown
	}
	if r.disabledValues == nil {
		r.disabledValues = map[string]bool{}
	}
	r.disabledValues[l.Label] = v
	r.gateEvents = append(r.gateEvents, v)
	if r.onGate != nil {
		r.onGate(v)
	}
	if r.gateAfterError {
		return ErrUnknown
	}
	return nil
}
func (r *fakeRunner) observeJob(_ context.Context, l layout, _ Target) (jobSnapshot, error) {
	state := r.states[l.Label]
	if state == absent {
		return jobSnapshot{State: absent}, nil
	}
	if state != matching || r.pidError || r.observeStarting {
		return jobSnapshot{}, ErrUnknown
	}
	if r.observeNoPID {
		return jobSnapshot{State: matching, StableNoPID: true}, nil
	}
	if r.pid < 2 {
		return jobSnapshot{}, ErrUnknown
	}
	return jobSnapshot{State: matching, PID: r.pid}, nil
}
func (r *fakeRunner) reboot(f *fakeFS, l layout) {
	r.states[l.Label] = absent
	if _, ok := f.objects[l.Plist]; ok && !r.disabledValues[l.Label] {
		r.states[l.Label] = matching
	}
}
