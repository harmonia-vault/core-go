//go:build windows

// 独立原生验收安装器：仅 fresh synthetic 资源；没有脚本解释器、密码输入或策略修改。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harmonia-vault/core-go/windowsservice"
	"golang.org/x/sys/windows"
)

var rejected = errors.New("native lab action rejected")

type profileFailure struct {
	Stage           string  `json:"stage"`
	Outcome         string  `json:"outcome"`
	HRESULTRecorded bool    `json:"hresultRecorded"`
	HRESULT         *uint32 `json:"hresult,omitempty"`
	ProfileListCode uint32  `json:"profileListCode"`
	DirectoryCode   uint32  `json:"directoryCode"`
}

type batchFailure struct {
	Stage             string  `json:"stage"`
	Outcome           string  `json:"outcome"`
	NTSTATUS          *uint32 `json:"ntstatus,omitempty"`
	NTSTATUSStage     string  `json:"ntstatusStage,omitempty"`
	NTSTATUSRecorded  bool    `json:"ntstatusRecorded"`
	EnumerationStatus uint32  `json:"enumerationStatus"`
	DirectRightCount  uint32  `json:"directRightCount"`
}

// 此数值来自经核对的 guest 输出，不能冒充原 installer 已同步记录的原生状态。
type taskObservedDiagnostic struct {
	Source       string `json:"source"`
	Stage        string `json:"stage"`
	HelperSHA256 string `json:"helperSHA256"`
	HRESULT      uint32 `json:"hresult"`
	SCODE        uint32 `json:"scode"`
	WCode        uint16 `json:"wcode"`
}

type taskFailure struct {
	Stage               string                  `json:"stage"`
	Outcome             string                  `json:"outcome"`
	HRESULTRecorded     bool                    `json:"hresultRecorded"`
	ObservedDiagnostic  *taskObservedDiagnostic `json:"observedDiagnostic,omitempty"`
	TaskCount           int64                   `json:"taskCount"`
	ChildFolderCount    int64                   `json:"childFolderCount"`
	StoppedServiceCount int                     `json:"stoppedServiceCount"`
}

type manifest struct {
	Schema              string           `json:"schema"`
	Nonce               string           `json:"nonce"`
	AccountName         string           `json:"accountName"`
	Install             string           `json:"install"`
	Phase               string           `json:"phase"`
	PendingAction       string           `json:"pendingAction"`
	FailureHistory      []profileFailure `json:"failureHistory,omitempty"`
	BatchNTSTATUS       *uint32          `json:"batchNTSTATUS,omitempty"`
	BatchStatusStage    string           `json:"batchStatusStage,omitempty"`
	BatchFailureHistory []batchFailure   `json:"batchFailureHistory,omitempty"`
	ProfileHRESULT      *uint32          `json:"profileHRESULT,omitempty"`
	TargetSID           string           `json:"targetSID"`
	SyncSID             string           `json:"syncSID"`
	BrokerSID           string           `json:"brokerSID"`
	AccountCreated      bool             `json:"accountCreated"`
	ProfileCreated      bool             `json:"profileCreated"`
	BatchGranted        bool             `json:"batchGranted"`
	RootCreated         bool             `json:"rootCreated"`
	FolderCreated       bool             `json:"folderCreated"`
	TaskRegistered      bool             `json:"taskRegistered"`
	TaskFailureHistory  []taskFailure    `json:"taskFailureHistory,omitempty"`
	Services            []string         `json:"services"`
	TaskFolder          string           `json:"taskFolder"`
	ProfileSHA256       string           `json:"profileSHA256"`
	SyncSHA256          string           `json:"syncSHA256"`
}

func (m *manifest) config() windowsservice.Config {
	return windowsservice.Config{Schema: windowsservice.Schema, TargetSID: m.TargetSID, SyncServiceSID: m.SyncSID, BrokerServiceSID: m.BrokerSID, Executable: filepath.Join(m.Install, "profile.exe"), SyncExecutable: filepath.Join(m.Install, "sync.exe"), ConfigurationFile: filepath.Join(m.Install, "profile.json")}
}
func installPath(nonce string) string { return `C:\Program Files\HarmoniaNative-` + nonce }
func (m *manifest) save() error {
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return rejected
	}
	path := filepath.Join(m.Install, "lab-manifest.json")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return rejected
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return rejected
	}
	return protect(path, adminFile)
}
func (m *manifest) begin(action string) error {
	if m.PendingAction != "" {
		return rejected
	}
	m.PendingAction = action
	m.Phase = action
	return m.save()
}
func (m *manifest) committed() error {
	m.PendingAction = ""
	return m.save()
}
func load(nonce string) (*manifest, error) { return loadManifest(nonce, "") }
func loadManifest(nonce string, allowedPending string) (*manifest, error) {
	path := filepath.Join(installPath(nonce), "lab-manifest.json")
	if protectedManifest(path) != nil {
		return nil, rejected
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 16384 {
		return nil, rejected
	}
	var m manifest
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return nil, rejected
	}
	if m.Schema != "harmonia/windows-native-lab/v2" || m.Nonce != nonce || m.Install != installPath(nonce) || m.AccountName != "harmonia-lab-"+nonce[:6] {
		return nil, rejected
	}
	if m.PendingAction != "" && m.PendingAction != allowedPending {
		return nil, rejected
	}
	if m.AccountCreated {
		sid, e := accountSID(m.AccountName)
		if e != nil || sid != m.TargetSID {
			return nil, rejected
		}
	}
	c := m.config()
	if m.TargetSID != "" {
		for _, n := range m.Services {
			if n != c.SyncServiceName() && n != c.BrokerServiceName() {
				return nil, rejected
			}
		}
	}
	return &m, nil
}
func hash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", rejected
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", rejected
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet("harmonia-native-lab", flag.ContinueOnError)
	nonce := fs.String("nonce", "", "新独占资源 nonce")
	stage := fs.String("stage", "", "已保护的合成传输目录")
	ph := fs.String("profile-sha256", "", "profile PE SHA256")
	sh := fs.String("sync-sha256", "", "sync PE SHA256")
	expectedSID := fs.String("expected-sid", "", "已独立核实的本次 exact SID")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(*nonce) {
		os.Exit(2)
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != "S-1-5-18" {
		os.Exit(3)
	}
	if mode != "resolve-profile-absent" && mode != "resolve-batch-absent" && mode != "resolve-task-absent" && mode != "resolve-task-absent-xml" && *expectedSID != "" {
		os.Exit(2)
	}
	var m *manifest
	switch mode {
	case "inspect":
		for _, proc := range []*windows.LazyProc{userAdd, userDel, groupAdd, createProfile, deleteProfile, logon, lsaOpen, lsaAdd, lsaRemove, lsaClose} {
			if proc.Find() != nil {
				e = rejected
				break
			}
		}
	case "provision":
		if *stage != `C:\Windows\Temp\harmonia-native-`+*nonce || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(*ph) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(*sh) {
			os.Exit(2)
		}
		m = &manifest{Schema: "harmonia/windows-native-lab/v2", Nonce: *nonce, AccountName: "harmonia-lab-" + (*nonce)[:6], Install: installPath(*nonce), ProfileSHA256: *ph, SyncSHA256: *sh, Services: []string{}}
		e = provision(m, *stage)
	case "resolve-profile-absent":
		if *stage != "" || *ph != "" || *sh != "" || *expectedSID == "" {
			os.Exit(2)
		}
		m, e = loadManifest(*nonce, "profile-create")
		if e == nil {
			e = resolveProfileAbsent(m, *expectedSID)
		}
	case "resolve-batch-absent":
		if *stage != "" || *ph != "" || *sh != "" || *expectedSID == "" {
			os.Exit(2)
		}
		m, e = loadManifest(*nonce, "batch-add")
		if e == nil {
			e = resolveBatchAbsent(m, *expectedSID)
		}
	case "resolve-task-absent":
		if *stage != "" || *ph != "" || *sh != "" || *expectedSID == "" {
			os.Exit(2)
		}
		m, e = loadManifest(*nonce, "task-self-register")
		if e == nil {
			e = resolveTaskAbsent(m, *expectedSID)
		}
	case "resolve-task-absent-xml":
		if *stage != "" || *ph != "" || *sh != "" || *expectedSID == "" {
			os.Exit(2)
		}
		m, e = loadManifest(*nonce, "task-self-register")
		if e == nil {
			e = resolveTaskAbsentXML(m, *expectedSID)
		}
	case "start", "cleanup":
		if *stage != "" || *ph != "" || *sh != "" {
			os.Exit(2)
		}
		m, e = load(*nonce)
		if e == nil {
			if mode == "start" {
				e = start(m)
			} else {
				e = cleanup(m)
			}
		}
	default:
		os.Exit(2)
	}
	if e != nil {
		phase := "preflight"
		if m != nil && m.Phase != "" {
			phase = m.Phase
		}
		fmt.Fprintf(os.Stderr, "NATIVE_LAB_FAIL phase=%s\n", phase)
		os.Exit(1)
	}
	fmt.Printf("NATIVE_LAB_PASS operation=%s\n", mode)
}
