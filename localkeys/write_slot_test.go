package localkeys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJournalSlotProtectedAndIsolated(t *testing.T) {
	config := testConfig(t)
	vault := openTest(t, config)
	data := []byte(`{"syntheticCiphertextReceipt":"synthetic-only-private-blob"}`)
	if err := vault.Save("writes-v1", data); err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(filepath.Join(config.Directory, "writes.v1.enc"))
	if err != nil || bytes.Contains(onDisk, data) || bytes.Contains(onDisk, []byte("synthetic-only-private-blob")) {
		t.Fatal("write journal not protected", err)
	}
	if _, err = vault.Load("writes-v2"); !errors.Is(err, ErrSlot) {
		t.Fatal("unknown journal slot allowed", err)
	}
	original, err := vault.Load("writes-v1")
	if err != nil || !bytes.Equal(original, data) {
		t.Fatal("journal roundtrip failed", err)
	}
	if err = vault.Delete("writes-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Load("writes-v1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal delete failed", err)
	}
}
