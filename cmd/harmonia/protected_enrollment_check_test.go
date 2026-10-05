//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/harmonia-vault/core-go/cryptox"
	"github.com/harmonia-vault/core-go/localkeys"
	"github.com/harmonia-vault/core-go/localstate"
	"github.com/harmonia-vault/core-go/syncclient"
)

// 使用公开已签向量，不用 Accepted 布尔代替密码学核验，也不宣称运行了新 PAKE。
func enrollmentMaterial(t *testing.T, version string) (localkeys.TrustContext, localkeys.DeviceKeys) {
	t.Helper()
	var context cryptox.EnrollmentContext
	var profile string
	var receipt any
	var seed, receiving []byte
	read := func(name string, into any) {
		data, e := os.ReadFile("../../cryptox/testdata/" + name + ".json")
		mustCLI(t, e)
		mustCLI(t, json.Unmarshal(data, into))
	}
	decode := func(text string) []byte {
		b, e := hex.DecodeString(text)
		mustCLI(t, e)
		return b
	}
	const key = "synthetic-local-check-receipt"
	switch version {
	case "5":
		var f struct {
			Approval cryptox.EnrollmentApprovalV5 `json:"approval"`
			Seeds    map[string]string            `json:"syntheticSeedsHex"`
		}
		read("recovery-dag-v1", &f)
		context, profile = f.Approval.Context, f.Approval.PairingProfile
		receipt = syncclient.EnrollmentReceiptV5{IdempotencyKey: key, Approval: f.Approval}
		seed, receiving = decode(f.Seeds["HEd"]), decode(f.Seeds["HX"])
	default:
		t.Fatal("测试版本错误")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	recv, e := ecdh.X25519().NewPrivateKey(receiving)
	mustCLI(t, e)
	keys := localkeys.DeviceKeys{DeviceID: context.InitiatorDeviceID, SigningSeed: seed, SigningPublic: private.Public().(ed25519.PublicKey), ReceivingPrivate: receiving, ReceivingPublic: recv.PublicKey().Bytes()}
	if cryptox.EncodeBase64(keys.SigningPublic) != context.InitiatorSigningPublicKey || cryptox.EncodeBase64(keys.ReceivingPublic) != context.InitiatorReceivingPublicKey {
		t.Fatal("向量私钥与双签证书不对应")
	}
	b, e := json.Marshal(receipt)
	mustCLI(t, e)
	return localkeys.TrustContext{Endpoint: "https://synthetic.example.invalid", AccountID: context.AccountID, AccountGeneration: 1, DeviceID: keys.DeviceID, SigningPublic: keys.SigningPublic, ReceivingPublic: keys.ReceivingPublic, CertificateVersion: version, PairingProfile: profile, EnrollmentCertificate: b, EnrollmentKey: key, Accepted: true}, keys
}

func seedEnrollmentCheck(t *testing.T, version string, mutate func(*localkeys.TrustContext, *localstate.State)) (string, string) {
	t.Helper()
	directory := protectedTestDirectory(t)
	uid, e := localkeys.CurrentUserID()
	mustCLI(t, e)
	s, e := localkeys.OpenEncryptedStateStore(localkeys.Config{Directory: directory, UserID: uid})
	mustCLI(t, e)
	defer s.Close()
	trust, keys := enrollmentMaterial(t, version)
	defer clear(keys.SigningSeed)
	defer clear(keys.ReceivingPrivate)
	mustCLI(t, s.Vault().SaveDeviceKeys(keys))
	state := localstate.EmptyState()
	if mutate != nil {
		mutate(&trust, &state)
	}
	// 直接加密保存故障输入，既有加载器和成熟验签器须拒绝；不是伪造测试通过的信任。
	b, e := json.Marshal(trust)
	mustCLI(t, e)
	mustCLI(t, s.Vault().Save("trust-v1", b))
	b, e = json.Marshal(state)
	mustCLI(t, e)
	mustCLI(t, s.Vault().Save("state-v1", b))
	return directory, uid
}

type checkFile struct {
	Mode  os.FileMode
	Size  int64
	Mod   time.Time
	Inode uint64
	Hash  [32]byte
}

func enrollmentFiles(t *testing.T, directory string) map[string]checkFile {
	t.Helper()
	result := map[string]checkFile{}
	mustCLI(t, filepath.WalkDir(directory, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		item := checkFile{Mode: info.Mode(), Size: info.Size(), Mod: info.ModTime(), Inode: info.Sys().(*syscall.Stat_t).Ino}
		if !entry.IsDir() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			item.Hash = sha256.Sum256(b)
		}
		result[strings.TrimPrefix(path, directory)] = item
		return nil
	}))
	return result
}
func runEnrollmentCheck(ctx context.Context, directory, uid string) (string, error, int32) {
	tr := &zeroHTTPTransport{}
	var out bytes.Buffer
	e := runWithRuntime(ctx, []string{"local-enrollment-check", "--local-directory", directory, "--local-user", uid}, &out, io.Discard, commandRuntime{httpClient: &http.Client{Transport: tr}, environment: noImportEnvironment{}})
	return out.String(), e, tr.calls.Load()
}

func TestLocalEnrollmentCheckSignedDAGReadOnlyNoHTTP(t *testing.T) {
	for _, version := range []string{"5"} {
		t.Run("cert"+version, func(t *testing.T) {
			dir, uid := seedEnrollmentCheck(t, version, nil)
			before := enrollmentFiles(t, dir)
			out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
			mustCLI(t, e)
			if out != "{\"version\":1,\"localEnrollmentVerified\":true}\n" || calls != 0 {
				t.Fatal("成功输出或HTTP边界错误")
			}
			if !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
				t.Fatal("只读检查改变文件集合/字节/inode/mode/mtime")
			}
		})
	}
}

func TestLocalEnrollmentCheckRevalidatesSignedStoredIssuerLedger(t *testing.T) {
	for _, version := range []string{"5"} {
		t.Run("cert"+version, func(t *testing.T) {
			dir, uid := seedEnrollmentCheck(t, version, nil)
			s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: dir, UserID: uid})
			mustCLI(t, e)
			trust, e := s.Vault().LoadTrustContext()
			mustCLI(t, e)
			keys, e := s.Vault().LoadDeviceKeys()
			mustCLI(t, e)
			defer clear(keys.SigningSeed)
			defer clear(keys.ReceivingPrivate)
			verifier, e := verifiedStoredContext(trust, keys)
			mustCLI(t, e)
			defer verifier.Close()
			// 无当前环境的下发仍须保存并重验完整签名来源账本；此处不调用 HTTP。
			cloud, e := verifier.VerifyPull(context.Background(), syncclient.Pull{Full: true, AccountID: trust.AccountID, AccountGeneration: "1", Sequence: 1000}, localstate.EmptyState().Cloud)
			mustCLI(t, e)
			if len(cloud.IssuerEvidence) == 0 {
				t.Fatal("成熟验签器没有产生来源账本")
			}
			state := localstate.EmptyState()
			state.Cloud = cloud
			mustCLI(t, s.Save(state))
			mustCLI(t, s.Close())
			before := enrollmentFiles(t, dir)
			out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
			mustCLI(t, e)
			if out == "" || calls != 0 || !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
				t.Fatal("已签账本重验违反只读边界")
			}
		})
	}
}

func TestLocalEnrollmentCheckRejectsStoredTrustAndLedger(t *testing.T) {
	for _, version := range []string{"5"} {
		for _, kind := range []string{"pending", "bad-signature", "wrong-generation", "wrong-device", "unknown-version", "closed", "missing-ledger", "corrupt-ledger"} {
			t.Run("cert"+version+"-"+kind, func(t *testing.T) {
				dir, uid := seedEnrollmentCheck(t, version, func(trust *localkeys.TrustContext, state *localstate.State) {
					switch kind {
					case "pending":
						trust.Accepted = false
					case "bad-signature":
						var r map[string]json.RawMessage
						mustCLI(t, json.Unmarshal(trust.EnrollmentCertificate, &r))
						var a map[string]json.RawMessage
						mustCLI(t, json.Unmarshal(r["approval"], &a))
						a["approverSignature"], _ = json.Marshal(cryptox.EncodeBase64(bytes.Repeat([]byte{91}, 64)))
						r["approval"], _ = json.Marshal(a)
						trust.EnrollmentCertificate, _ = json.Marshal(r)
					case "wrong-generation":
						trust.AccountGeneration = 2
					case "wrong-device":
						trust.DeviceID = "different-device"
					case "unknown-version":
						trust.CertificateVersion = "999"
					case "closed":
						state.AccountClosed = true
					case "missing-ledger", "corrupt-ledger":
						state.Cloud.AccountID, state.Cloud.AccountGeneration, state.Cloud.Sequence = trust.AccountID, trust.AccountGeneration, 1
						if kind == "corrupt-ledger" {
							state.Cloud.IssuerEvidence = []byte(`{"profile":"attacker"}`)
						}
					}
				})
				before := enrollmentFiles(t, dir)
				out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
				if e == nil || out != "" || calls != 0 {
					t.Fatal("错误材料假成功或联网", e)
				}
				if !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
					t.Fatal("拒绝检查写材料")
				}
			})
		}
	}
}

func TestLocalEnrollmentCheckMissingAndBusyNeverCreatesOrWrites(t *testing.T) {
	uid, e := localkeys.CurrentUserID()
	mustCLI(t, e)
	t.Run("absent", func(t *testing.T) {
		dir := protectedTestDirectory(t)
		out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
		if e == nil || out != "" || calls != 0 {
			t.Fatal("缺目录假成功")
		}
		if _, e = os.Lstat(dir); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("缺目录被创建", e)
		}
	})
	for _, missing := range []string{"machine-key.v1", "vault.lock", "device-v1", "trust-v1"} {
		t.Run(missing, func(t *testing.T) {
			dir, uid := seedEnrollmentCheck(t, "5", nil)
			filename := missing
			if missing == "device-v1" || missing == "trust-v1" {
				s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: dir, UserID: uid})
				mustCLI(t, e)
				mustCLI(t, s.Vault().Delete(missing))
				mustCLI(t, s.Close())
			} else {
				mustCLI(t, os.Remove(filepath.Join(dir, filename)))
			}
			before := enrollmentFiles(t, dir)
			out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
			if e == nil || out != "" || calls != 0 {
				t.Fatal("缺材料假成功")
			}
			if !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
				t.Fatal("缺材料被初始化")
			}
		})
	}
	t.Run("busy", func(t *testing.T) {
		dir, uid := seedEnrollmentCheck(t, "5", nil)
		s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: dir, UserID: uid})
		mustCLI(t, e)
		defer s.Close()
		before := enrollmentFiles(t, dir)
		out, e, calls := runEnrollmentCheck(context.Background(), dir, uid)
		if !errors.Is(e, localkeys.ErrBusy) || out != "" || calls != 0 || !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
			t.Fatal("真实owner锁忙没有拒绝", e)
		}
	})
}

type checkObservedStore struct {
	*localkeys.StateStore
	writes, closes int
	closeError     error
	cancel         context.CancelFunc
}

func (s *checkObservedStore) Save(localstate.State) error {
	s.writes++
	return errors.New("只读检查不能Save")
}
func (s *checkObservedStore) Close() error {
	s.closes++
	e := s.StateStore.Close()
	if s.cancel != nil {
		s.cancel()
	}
	return errors.Join(e, s.closeError)
}
func TestLocalEnrollmentCheckCloseAndCancelCannotReportSuccess(t *testing.T) {
	for _, kind := range []string{"success", "close-failure", "cancel-before", "cancel-on-close", "verification-failure-and-close"} {
		t.Run(kind, func(t *testing.T) {
			dir, uid := seedEnrollmentCheck(t, "5", func(trust *localkeys.TrustContext, _ *localstate.State) {
				if kind == "verification-failure-and-close" {
					trust.Accepted = false
				}
			})
			s, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: dir, UserID: uid})
			mustCLI(t, e)
			failure := errors.New("合成Close失败")
			observed := &checkObservedStore{StateStore: s}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "close-failure" || kind == "verification-failure-and-close" {
				observed.closeError = failure
			}
			if kind == "cancel-before" {
				cancel()
			}
			if kind == "cancel-on-close" {
				observed.cancel = cancel
			}
			before := enrollmentFiles(t, dir)
			var out bytes.Buffer
			e = checkAndCloseLocalEnrollment(ctx, observed, &out)
			if kind == "success" {
				mustCLI(t, e)
				if out.Len() == 0 {
					t.Fatal("没有成功结果")
				}
			} else if e == nil || out.Len() != 0 {
				t.Fatal("Close/取消/核验失败假成功", e)
			}
			if observed.closeError != nil && !errors.Is(e, failure) {
				t.Fatal("Close失败被吞", e)
			}
			if observed.writes != 0 || observed.closes != 1 || !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
				t.Fatal("只读/单次Close约束失败")
			}
			reopened, e := localkeys.OpenExistingEncryptedStateStore(localkeys.Config{Directory: dir, UserID: uid})
			mustCLI(t, e)
			mustCLI(t, reopened.Close())
		})
	}
}

func TestLocalEnrollmentCheckArgumentsDoNotOpenExtraInputs(t *testing.T) {
	dir, uid := seedEnrollmentCheck(t, "5", nil)
	base := []string{"local-enrollment-check", "--local-directory", dir, "--local-user", uid}
	for _, extra := range [][]string{{"--server", "https://synthetic.invalid"}, {"--ca-file", "/synthetic-never-open"}, {"--fixture"}, {"--offline-local=false"}, {"--current-env"}, {"--once"}, {"extra"}} {
		t.Run(strings.Join(extra, "-"), func(t *testing.T) {
			tr := &zeroHTTPTransport{}
			var out bytes.Buffer
			before := enrollmentFiles(t, dir)
			e := runWithRuntime(context.Background(), append(append([]string{}, base...), extra...), &out, io.Discard, commandRuntime{httpClient: &http.Client{Transport: tr}, environment: noImportEnvironment{}})
			if e == nil || out.Len() != 0 || tr.calls.Load() != 0 || !reflect.DeepEqual(before, enrollmentFiles(t, dir)) {
				t.Fatal("额外参数没有前置拒绝", e)
			}
		})
	}
	for _, args := range [][]string{{"local-enrollment-check"}, {"local-enrollment-check", "--local-directory", dir, "--local-user", "0"}, {"local-enrollment-check", "--local-directory", "relative", "--local-user", uid}, {"local-enrollment-check", "--local-directory", dir + "/.", "--local-user", uid}} {
		if e := run(context.Background(), args, io.Discard, io.Discard); e == nil {
			t.Fatal("无明确规范身份路径仍成功")
		}
	}
}
