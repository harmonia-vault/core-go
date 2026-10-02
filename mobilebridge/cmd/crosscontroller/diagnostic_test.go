package main

import (
	"bytes"
	"sync"
	"testing"
)

func TestDiagnosticConcurrentBoundedCategoriesAndClear(t *testing.T) {
	var d boundedDiagnostic
	d.Write([]byte("synthetic-private-value invalid Harmonia v1 wire value"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				d.Write(bytes.Repeat([]byte{'x'}, 4096))
				for _, category := range d.categories() {
					if category != "invalid Harmonia v1 wire value" {
						t.Error("unexpected diagnostic category")
					}
				}
			}
		})
	}
	wg.Wait()
	if len(d.data) != 32768 {
		t.Fatal("diagnostic exceeded bound")
	}
	reference := d.data
	d.clear()
	if len(d.categories()) != 0 || !bytes.Equal(reference, make([]byte, len(reference))) {
		t.Fatal("diagnostic not cleared")
	}
}
