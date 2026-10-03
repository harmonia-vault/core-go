package linuxinstall

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"

	"github.com/harmonia-vault/core-go/cryptox"
)

const ReceiptSchema = "harmonia/linux-installation/v1"
const JournalSchema = "harmonia/linux-uninstall-journal/v1"
const MaxRecordBytes = 65536

type Receipt struct {
	Schema         string     `json:"schema"`
	InstallationID string     `json:"installationId"`
	Plan           Plan       `json:"plan"`
	UnitSHA256     string     `json:"unitSha256"`
	Phase          string     `json:"phase"`
	Revision       uint64     `json:"revision,omitempty"`
	Creations      []Creation `json:"creations,omitempty"`
	HandoffIntent  bool       `json:"handoffIntent,omitempty"`
	EnableIntent   bool       `json:"enableIntent,omitempty"`
	EnableIdentity *Identity  `json:"enableIdentity,omitempty"`
}

func (r Receipt) Validate() error {
	if r.Schema != ReceiptSchema || !installationID.MatchString(r.InstallationID) || r.Plan.Validate() != nil || !digest.MatchString(r.UnitSHA256) {
		return ErrState
	}
	if _, err := r.unitTemplate(); err != nil {
		return ErrState
	}
	if err := validateCreationRecord(r); err != nil {
		return err
	}
	switch r.Phase {
	case "install-planned", "installed-disabled", "enabled":
		return nil
	}
	return ErrState
}

// Identity 只记录已核文件身份；没有材料/值/任意删除路径。
type Identity struct {
	Area       string `json:"area"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Mode       uint32 `json:"mode"`
	Links      uint64 `json:"links"`
	LinkTarget string `json:"linkTarget,omitempty"`
}
type Deletion struct {
	Object  Identity `json:"object"`
	Intent  bool     `json:"intent"`
	Removed bool     `json:"removed"`
}
type Journal struct {
	Schema         string     `json:"schema"`
	InstallationID string     `json:"installationId"`
	Plan           Plan       `json:"plan"`
	Phase          string     `json:"phase"`
	Revision       uint64     `json:"revision"`
	Deletions      []Deletion `json:"deletions"`
	Receipt        *Receipt   `json:"receipt,omitempty"`
}

var journalPhases = map[string]int{"uninstall-requested": 0, "service-drained": 1, "offline-closed": 2, "cleanup-authorized": 3, "files-removed": 4, "unit-removed": 5, "program-removed": 6, "completed": 7}
var accountNames = map[string]bool{"device.v1.enc": true, "session.v1.enc": true, "trust.v1.enc": true, "writes.v1.enc": true, "recovery.dag.v1.enc": true}
var stateNames = map[string]bool{"machine-key.v1": true, "state.v1.enc": true, "provider.v1.enc": true, "environment.sh": true, "vault.lock": true}
var ipcNames = map[string]string{"ipc.lock": "file", "ipc-owner.json": "file", "harmonia.sock": "socket"}

func (i Identity) validate(p Plan) error {
	if i.Inode == 0 || i.Name == "" || filepath.Base(i.Name) != i.Name || i.Links == 0 {
		return ErrState
	}
	uid, _ := strconv.ParseUint(p.Input.UID, 10, 32)
	gid, _ := strconv.ParseUint(p.Input.GID, 10, 32)
	wantUID, wantGID, mode, kind := uint32(0), uint32(0), uint32(0), "file"
	switch i.Area {
	case "state":
		if !stateNames[i.Name] || accountNames[i.Name] {
			return ErrState
		}
		wantUID, wantGID, mode = uint32(uid), uint32(gid), 0600
	case "ipc":
		var ok bool
		kind, ok = ipcNames[i.Name]
		if !ok {
			return ErrState
		}
		wantUID, wantGID, mode = uint32(uid), uint32(gid), 0600
	case "state-directory":
		if i.Name != p.Input.UID {
			return ErrState
		}
		kind, mode = "directory", 0700
	case "ipc-directory":
		if i.Name != "ipc" {
			return ErrState
		}
		kind, mode = "directory", 0700
	case "program":
		if i.Name == "harmonia" {
			mode = 0755
		} else if i.Name == "ca.pem" && p.CAPath != "" {
			mode = 0644
		} else {
			return ErrState
		}
	case "program-directory":
		if i.Name != p.Input.UID {
			return ErrState
		}
		kind, mode = "directory", 0755
		if i.Mode == 0700 {
			mode = 0700
		}
	case "unit":
		if i.Name != p.UnitName {
			return ErrState
		}
		mode = 0644
	case "enable-link":
		if i.Name != p.UnitName || i.LinkTarget != p.UnitPath && i.LinkTarget != "../"+p.UnitName {
			return ErrState
		}
		kind, mode = "symlink", 0777
	default:
		return ErrState
	}
	if i.Kind != kind || i.UID != wantUID || i.GID != wantGID || i.Mode != mode || kind != "directory" && i.Links != 1 || kind != "symlink" && i.LinkTarget != "" {
		return ErrState
	}
	return nil
}
func (j Journal) Validate() error {
	stage, ok := journalPhases[j.Phase]
	if !ok || j.Schema != JournalSchema || !installationID.MatchString(j.InstallationID) || j.Plan.Validate() != nil || j.Revision == 0 || len(j.Deletions) > 32 {
		return ErrState
	}
	if j.Receipt != nil && (j.Receipt.Validate() != nil || j.Receipt.Revision == 0 || j.Receipt.Plan != j.Plan || j.Receipt.InstallationID != j.InstallationID) {
		return ErrState
	}
	if stage < 3 && len(j.Deletions) != 0 {
		return ErrState
	}
	seen := map[string]bool{}
	for _, d := range j.Deletions {
		key := d.Object.Area + "/" + d.Object.Name
		if seen[key] || d.Object.validate(j.Plan) != nil || d.Removed && !d.Intent {
			return ErrState
		}
		seen[key] = true
	}
	if stage >= 3 {
		required := []string{"state-directory/" + j.Plan.Input.UID, "program-directory/" + j.Plan.Input.UID, "program/harmonia", "unit/" + j.Plan.UnitName}
		if j.Receipt != nil {
			if j.Receipt.Validate() != nil || j.Receipt.Revision == 0 || j.Receipt.Plan != j.Plan || j.Receipt.InstallationID != j.InstallationID {
				return ErrState
			}
			required = nil
			for _, c := range j.Receipt.Creations {
				if c.Observed != nil {
					required = append(required, c.Area+"/"+c.Name)
				}
			}
			if j.Receipt.EnableIdentity != nil {
				required = append(required, "enable-link/"+j.Plan.UnitName)
			}
		}
		for _, key := range required {
			if !seen[key] {
				return ErrState
			}
		}
		if j.Receipt == nil && j.Plan.CAPath != "" && !seen["program/ca.pem"] {
			return ErrState
		}
	}
	for _, d := range j.Deletions {
		area := d.Object.Area
		must := stage >= 4 && (area == "state" || area == "ipc" || area == "state-directory" || area == "ipc-directory") || stage >= 5 && (area == "unit" || area == "enable-link") || stage >= 6 && (area == "program" || area == "program-directory")
		if must && !d.Removed {
			return ErrState
		}
	}
	return nil
}

func decodeRecord(data []byte, out any) error {
	if err := cryptox.ValidateStrictJSON(data, MaxRecordBytes); err != nil {
		return ErrState
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrState
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrState
	}
	return nil
}
func DecodeReceipt(data []byte) (Receipt, error) {
	var r Receipt
	if decodeRecord(data, &r) != nil || r.Validate() != nil {
		return Receipt{}, ErrState
	}
	return r, nil
}
func DecodeJournal(data []byte) (Journal, error) {
	var j Journal
	if decodeRecord(data, &j) != nil || j.Validate() != nil {
		return Journal{}, ErrState
	}
	return j, nil
}

// ValidateSuccessor 在持久 CAS 前拒绝倒退、换安装/原计划、替换删除对象与跳阶段。
// cleanup-authorized 的首次建立仍需协调器实际离线退出/冻结/锁证明，不能只依赖历史记录。
func ValidateSuccessor(previous, next Journal) error {
	if previous.Validate() != nil || next.Validate() != nil || previous.Plan != next.Plan || previous.InstallationID != next.InstallationID || previous.Revision == ^uint64(0) || next.Revision != previous.Revision+1 {
		return ErrState
	}
	oldReceipt, _ := json.Marshal(previous.Receipt)
	newReceipt, _ := json.Marshal(next.Receipt)
	if !bytes.Equal(oldReceipt, newReceipt) {
		return ErrState
	}
	a, b := journalPhases[previous.Phase], journalPhases[next.Phase]
	if b < a || b > a+1 {
		return ErrState
	}
	if a < 3 && b < 3 {
		return nil
	}
	if a == 2 && b == 3 {
		for _, d := range next.Deletions {
			if d.Intent || d.Removed {
				return ErrState
			}
		}
		return nil
	}
	if len(previous.Deletions) != len(next.Deletions) {
		return ErrState
	}
	changes := 0
	for n, old := range previous.Deletions {
		d := next.Deletions[n]
		if old.Object != d.Object || old.Intent && !d.Intent || old.Removed && !d.Removed || !old.Intent && d.Removed {
			return ErrState
		}
		if old.Intent != d.Intent || old.Removed != d.Removed {
			changes++
		}
	}
	if changes > 1 || a != b && changes != 0 {
		return ErrState
	}
	return nil
}

// MissingObjectAllowed 只用于已持久写入原对象删除意图后的中断续做。
func MissingObjectAllowed(j Journal, index int) bool {
	return j.Validate() == nil && journalPhases[j.Phase] >= 3 && index >= 0 && index < len(j.Deletions) && j.Deletions[index].Intent
}
