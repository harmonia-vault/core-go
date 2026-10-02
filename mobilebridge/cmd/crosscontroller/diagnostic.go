package main

import (
	"bytes"
	"sync"
)

// boundedDiagnostic只保留隔离子进程的有界内存，输出只能是固定类别。
// daemon仍在写入时允许查询；任何原始错误/值/凭据均不回显或存盘。
type boundedDiagnostic struct {
	mu   sync.Mutex
	data []byte
}

func (d *boundedDiagnostic) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	const limit = 32768
	n := len(p)
	if remaining := limit - len(d.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		d.data = append(d.data, p...)
	}
	return n, nil
}
func (d *boundedDiagnostic) categories() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result []string
	for _, category := range []string{"invalid Harmonia v1 wire value", "invalid Ed25519 signature", "legacy cache exceeds", "cert3 cached state", "issuer-origin", "evidence", "receipt", "回执", "fragment", "权限", "directory", "x509", "400", "401", "403", "409", "timeout", "deadline"} {
		if bytes.Contains(d.data, []byte(category)) {
			result = append(result, category)
		}
	}
	return result
}
func (d *boundedDiagnostic) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.data)
	d.data = nil
}
