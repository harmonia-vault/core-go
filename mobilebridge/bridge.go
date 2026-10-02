// Package mobilebridge 是 Go 核心的窄移动边界；Dart 不接触私钥或密码学算法。
package mobilebridge

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/pairing"
)

const materialHeader = "HARMKEY1"
const maximumCommand = 4096

var errInput = errors.New("invalid mobile bridge command")
var errClosed = errors.New("device is locked or closed")
var errNotEnrolled = errors.New("trusted enrollment and mobile synchronization are not connected")

// Device 只由原生平台临时持有。平台每次认证解包后导入，操作完立即 Close。
// 未完成可信入网的公钥不成为可信设备；本切片不提供任意消息签名接口。
type Device struct {
	mu        sync.Mutex
	signing   ed25519.PrivateKey
	receiving []byte
}

func NewDevice() (*Device, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("device key generation failed")
	}
	_, receiving, err := cryptox.GenerateReceivingKey()
	if err != nil {
		clear(signing)
		return nil, errors.New("device key generation failed")
	}
	return &Device{signing: signing, receiving: receiving}, nil
}

// ImportProtectedMaterial 只能由平台成功认证和 AES-GCM 解包后调用；不经 MethodChannel。
func ImportProtectedMaterial(material []byte) (*Device, error) {
	if len(material) != len(materialHeader)+64 || string(material[:len(materialHeader)]) != materialHeader {
		return nil, errors.New("invalid protected device material")
	}
	seed := material[len(materialHeader) : len(materialHeader)+32]
	receiving := bytes.Clone(material[len(materialHeader)+32:])
	if bytes.Equal(seed, make([]byte, 32)) || bytes.Equal(receiving, make([]byte, 32)) {
		clear(receiving)
		return nil, errors.New("invalid protected device material")
	}
	if _, err := ecdh.X25519().NewPrivateKey(receiving); err != nil {
		clear(receiving)
		return nil, errors.New("invalid protected device material")
	}
	return &Device{signing: ed25519.NewKeyFromSeed(seed), receiving: receiving}, nil
}

// ExportProtectedMaterial 仅供原生 AES 包封。返回值含私钥，禁止返回 Dart、写日志或明文持久化。
// Go/JNI/Android 运行时可能复制字节；Close/clear 不承诺消除所有运行时副本。
func (d *Device) ExportProtectedMaterial() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.signing) != 64 || len(d.receiving) != 32 {
		return nil, errClosed
	}
	out := make([]byte, len(materialHeader)+64)
	copy(out, materialHeader)
	copy(out[len(materialHeader):], d.signing[:32])
	copy(out[len(materialHeader)+32:], d.receiving)
	return out, nil
}
func (d *Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.signing)
	clear(d.receiving)
	d.signing = nil
	d.receiving = nil
}

func ProtocolVersion() int { return 1 }
func Hash256(input []byte) ([]byte, error) {
	if len(input) > 16384 {
		return nil, errInput
	}
	digest := sha256.Sum256(input)
	return digest[:], nil
}

func capabilities() map[string]any {
	return map[string]any{"version": 1, "goCore": true, "pairingNative": pairing.NativeAvailable(), "pairingProfile": pairing.Profile, "realVaultReady": false, "softwareDeviceKeys": true}
}

type command struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Endpoint  string `json:"endpoint,omitempty"`
}

func parseCommand(raw string) (command, error) {
	var c command
	if len(raw) == 0 || len(raw) > maximumCommand || !utf8.ValidString(raw) {
		return c, errInput
	}
	// 只接受扁平、唯一字段；encoding/json 默认会静默接受重复字段。
	dec := json.NewDecoder(strings.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return c, errInput
	}
	seen := map[string]bool{}
	for dec.More() {
		token, err = dec.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return c, errInput
		}
		seen[key] = true
		var value any
		if dec.Decode(&value) != nil {
			return c, errInput
		}
		switch key {
		case "version":
			n, ok := value.(float64)
			if !ok || n != 1 {
				return c, errInput
			}
			c.Version = 1
		case "operation":
			s, ok := value.(string)
			if !ok {
				return c, errInput
			}
			c.Operation = s
		case "endpoint":
			s, ok := value.(string)
			if !ok {
				return c, errInput
			}
			c.Endpoint = s
		default:
			return c, errInput
		}
	}
	if _, err = dec.Token(); err != nil {
		return c, errInput
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || c.Version != 1 || c.Operation == "" {
		return c, errInput
	}
	if c.Operation == "validateEndpoint" {
		if !seen["endpoint"] {
			return c, errInput
		}
	} else if seen["endpoint"] {
		return c, errInput
	}
	return c, nil
}
func encode(value any) (string, error) { b, err := json.Marshal(value); return string(b), err }

// ExecutePublic 不进行网络、设备解包、签名或秘密读取。
func ExecutePublic(raw string) (string, error) {
	c, err := parseCommand(raw)
	if err != nil {
		return "", err
	}
	switch c.Operation {
	case "capabilities":
		return encode(capabilities())
	case "validateEndpoint":
		endpoint, err := validateEndpoint(c.Endpoint)
		if err != nil {
			return "", err
		}
		return encode(map[string]any{"version": 1, "endpoint": endpoint})
	case "selfTest":
		return NativeSelfTest()
	default:
		return "", errInput
	}
}

// Execute 是认证后有限业务接口。安全操作仍拒绝；不能凭界面 role 或 nativeReady 绕过入网。
func (d *Device) Execute(raw string) (string, error) {
	c, err := parseCommand(raw)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.signing) != 64 || len(d.receiving) != 32 {
		return "", errClosed
	}
	switch c.Operation {
	case "publicInfo":
		receive, _ := ecdh.X25519().NewPrivateKey(d.receiving)
		sign := d.signing.Public().(ed25519.PublicKey)
		id := sha256.Sum256(sign)
		return encode(map[string]any{"version": 1, "deviceId": hex.EncodeToString(id[:]), "signingPublicKey": cryptox.EncodeBase64(sign), "receivingPublicKey": cryptox.EncodeBase64(receive.PublicKey().Bytes()), "trusted": false})
	case "cryptoCheck":
		if err := checkCrypto(d.signing, d.receiving); err != nil {
			return "", err
		}
		return encode(map[string]any{"version": 1, "ed25519": true, "hpke": true, "aead": true, "tamperingRejected": true, "trusted": false})
	case "pull", "submit", "approveDevice", "revokeDevice", "recover":
		return "", errNotEnrolled
	default:
		return "", errInput
	}
}

var dnsName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var pathPart = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

func validateEndpoint(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.TrimSpace(raw) != raw || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\\x00\r\n\t") {
		return "", errInput
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.RawPath != "" {
		return "", errInput
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return "", errInput
		}
		for _, part := range strings.Split(host, ".") {
			if !dnsName.MatchString(part) {
				return "", errInput
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errInput
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", errInput
	}
	for _, part := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if part == "" {
			if u.Path != "" && u.Path != "/" {
				return "", errInput
			}
			continue
		}
		if part == "." || part == ".." || !pathPart.MatchString(part) {
			return "", errInput
		}
	}
	if strings.Contains(u.Path, "//") {
		return "", errInput
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func checkCrypto(signing ed25519.PrivateKey, receiving []byte) error {
	plaintext := []byte("harmonia-synthetic-native-check")
	defer clear(plaintext)
	signature := ed25519.Sign(signing, plaintext)
	if !ed25519.Verify(signing.Public().(ed25519.PublicKey), plaintext, signature) {
		return errors.New("native cryptographic check failed")
	}
	signature[0] ^= 1
	if ed25519.Verify(signing.Public().(ed25519.PublicKey), plaintext, signature) {
		return errors.New("signature tampering accepted")
	}
	key, err := cryptox.GenerateEnvironmentKey()
	if err != nil {
		return err
	}
	defer clear(key)
	receive, err := ecdh.X25519().NewPrivateKey(receiving)
	if err != nil {
		return err
	}
	envelope := cryptox.EnvelopeContext{AccountID: "native-check", AccountGeneration: "1", EnvironmentID: "synthetic", KeyVersion: "1", RecipientType: "device", RecipientID: "native-device", RecipientGeneration: "1", RecipientPublicKey: cryptox.EncodeBase64(receive.PublicKey().Bytes())}
	wrapped, err := cryptox.WrapEnvironmentKey(key, envelope)
	if err != nil {
		return err
	}
	unwrapped, err := cryptox.UnwrapEnvironmentKey(receiving, envelope, wrapped)
	if err != nil {
		return err
	}
	defer clear(unwrapped)
	if !bytes.Equal(key, unwrapped) {
		return errors.New("HPKE check failed")
	}
	changedEnvelope := envelope
	changedEnvelope.AccountID = "substitution"
	if k, err := cryptox.UnwrapEnvironmentKey(receiving, changedEnvelope, wrapped); err == nil {
		clear(k)
		return errors.New("HPKE context substitution accepted")
	}
	value := cryptox.ValueContext{AccountID: "native-check", AccountGeneration: "1", EnvironmentID: "synthetic", KeyVersion: "1", Name: "SYNTHETIC_NATIVE"}
	packet, err := cryptox.EncryptValue(unwrapped, value, plaintext)
	if err != nil {
		return err
	}
	plain, err := cryptox.DecryptValue(unwrapped, value, packet)
	if err != nil {
		return err
	}
	defer clear(plain)
	if !bytes.Equal(plaintext, plain) {
		return errors.New("AEAD check failed")
	}
	packet[len(packet)-1] ^= 1
	if p, err := cryptox.DecryptValue(unwrapped, value, packet); err == nil {
		clear(p)
		return errors.New("AEAD tampering accepted")
	}
	return nil
}
