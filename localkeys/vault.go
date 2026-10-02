// Package localkeys 保存服务可用的机器保护材料与加密状态。
// 软件钥匙可在无人登录时使用，不承诺抵抗已控制 root/管理员或解锁磁盘的攻击者。
package localkeys

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxRecordSize = 32 << 20
const maxKeyRecordSize = 64 << 10
const keyFile = "machine-key.v1"
const keySchema = "harmonia/local-machine-key/v1"
const recordSchema = "harmonia/local-encrypted-record/v1"

var (
	ErrIdentity   = errors.New("local user identity mismatch")
	ErrPermission = errors.New("local key directory or file permissions are unsafe")
	ErrCorrupt    = errors.New("local encrypted state is invalid or authentication failed")
	ErrClosed     = errors.New("local key store is closed")
	ErrBusy       = errors.New("local key store is already owned by another process")
	ErrSlot       = errors.New("unsupported local state slot")
	ErrFixture    = errors.New("synthetic fixture state cannot enter encrypted service state")
)

// Config 的目录必须是明确、绝对、无符号链接的路径。父目录须预先存在。
// UserID 是本地 UID 或目标用户 SID；ServiceSID 只供 Windows 专用服务身份使用。
type Config struct {
	Directory  string
	UserID     string
	ServiceSID string
}
type machineKeyRecord struct {
	Schema       string `json:"schema"`
	UserID       string `json:"userId"`
	OwnerID      string `json:"ownerId"`
	Protector    string `json:"protector"`
	KeyID        string `json:"keyId"`
	ProtectedKey []byte `json:"protectedKey"`
}
type encryptedRecord struct {
	Schema     string `json:"schema"`
	UserID     string `json:"userId"`
	OwnerID    string `json:"ownerId"`
	KeyID      string `json:"keyId"`
	Slot       string `json:"slot"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type associatedData struct {
	Domain  string `json:"domain"`
	UserID  string `json:"userId"`
	OwnerID string `json:"ownerId"`
	KeyID   string `json:"keyId"`
	Slot    string `json:"slot"`
}

// Vault 的独占锁覆盖全部固定 slot。应用只让后台服务持有，CLI 通过验证身份的 IPC 请求操作。
type Vault struct {
	mu        sync.Mutex
	fs        secureFS
	config    Config
	ownerID   string
	key       []byte
	keyID     string
	keyDigest [32]byte
	closed    bool
}

var slots = map[string]string{"state-v1": "state.v1.enc", "device-v1": "device.v1.enc", "session-v1": "session.v1.enc", "trust-v1": "trust.v1.enc", "provider-v1": "provider.v1.enc", "windows-originals-v1": "windows-originals.v1.enc"}

func strictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return ErrCorrupt
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}
func keyID(key []byte) string { sum := sha256.Sum256(key); return hex.EncodeToString(sum[:]) }

func Open(c Config) (*Vault, error) {
	fs, owner, err := openSecureFS(c)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Vault, error) { fs.Close(); return nil, err }
	v := &Vault{fs: fs, config: c, ownerID: owner}
	content, err := fs.Read(keyFile, maxKeyRecordSize)
	if errors.Is(err, os.ErrNotExist) {
		// 旧状态仍在时绝不能默默换机器钥，否则会伪装成空 vault。
		for _, name := range slots {
			if _, e := fs.Read(name, maxRecordSize); e == nil {
				return fail(ErrCorrupt)
			} else if !errors.Is(e, os.ErrNotExist) {
				return fail(e)
			}
		}
		key := make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return fail(err)
		}
		protected, err := protectMachineKey(key, c, owner)
		if err != nil {
			clear(key)
			return fail(err)
		}
		record := machineKeyRecord{Schema: keySchema, UserID: c.UserID, OwnerID: owner, Protector: protectorName(), KeyID: keyID(key), ProtectedKey: protected}
		data, err := json.Marshal(record)
		if err != nil {
			clear(key)
			return fail(err)
		}
		if err := fs.Write(keyFile, data, true); err != nil {
			clear(key)
			clear(protected)
			return fail(err)
		}
		v.keyDigest = sha256.Sum256(data)
		clear(protected)
		clear(data)
		v.key = key
		v.keyID = record.KeyID
	} else if err != nil {
		return fail(err)
	} else {
		v.keyDigest = sha256.Sum256(content)
		var record machineKeyRecord
		if err := strictJSON(content, &record); err != nil {
			return fail(err)
		}
		if record.Schema != keySchema || record.UserID != c.UserID || record.OwnerID != owner || record.Protector != protectorName() {
			return fail(ErrIdentity)
		}
		key, err := unprotectMachineKey(record.ProtectedKey, c, owner)
		clear(record.ProtectedKey)
		clear(content)
		if err != nil || len(key) != chacha20poly1305.KeySize || record.KeyID != keyID(key) {
			clear(key)
			return fail(ErrCorrupt)
		}
		v.key = key
		v.keyID = record.KeyID
	}
	return v, nil
}
func (v *Vault) ensureKey() error {
	data, err := v.fs.Read(keyFile, maxKeyRecordSize)
	if err != nil {
		return err
	}
	defer clear(data)
	if sha256.Sum256(data) != v.keyDigest {
		return ErrCorrupt
	}
	return nil
}
func (v *Vault) aead() (cipher.AEAD, error) {
	if v.closed {
		return nil, ErrClosed
	}
	return chacha20poly1305.NewX(v.key)
}
func (v *Vault) aad(slot string) []byte {
	data, _ := json.Marshal(associatedData{Domain: recordSchema, UserID: v.config.UserID, OwnerID: v.ownerID, KeyID: v.keyID, Slot: slot})
	return data
}
func (v *Vault) Load(slot string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.loadLocked(slot)
}
func (v *Vault) loadLocked(slot string) ([]byte, error) {
	if v.closed {
		return nil, ErrClosed
	}
	name, ok := slots[slot]
	if !ok {
		return nil, ErrSlot
	}
	if err := v.ensureKey(); err != nil {
		return nil, err
	}
	data, err := v.fs.Read(name, maxRecordSize)
	if err != nil {
		return nil, err
	}
	var record encryptedRecord
	if err := strictJSON(data, &record); err != nil {
		return nil, err
	}
	if record.Schema != recordSchema || record.UserID != v.config.UserID || record.OwnerID != v.ownerID || record.KeyID != v.keyID || record.Slot != slot || len(record.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrCorrupt
	}
	aead, err := v.aead()
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, v.aad(slot))
	if err != nil {
		return nil, ErrCorrupt
	}
	return plaintext, nil
}
func (v *Vault) Save(slot string, plaintext []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.saveLocked(slot, plaintext)
}
func (v *Vault) saveLocked(slot string, plaintext []byte) error {
	if v.closed {
		return ErrClosed
	}
	name, ok := slots[slot]
	if !ok {
		return ErrSlot
	}
	if err := v.ensureKey(); err != nil {
		return err
	}
	if len(plaintext) > 16<<20 {
		return fmt.Errorf("local state exceeds limit")
	}
	aead, err := v.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	record := encryptedRecord{Schema: recordSchema, UserID: v.config.UserID, OwnerID: v.ownerID, KeyID: v.keyID, Slot: slot, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, v.aad(slot))}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return v.fs.Write(name, data, false)
}
func (v *Vault) Delete(slot string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	name, ok := slots[slot]
	if !ok {
		return ErrSlot
	}
	if err := v.ensureKey(); err != nil {
		return err
	}
	return v.fs.Delete(name)
}
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	clear(v.key)
	v.key = nil
	return v.fs.Close()
}
