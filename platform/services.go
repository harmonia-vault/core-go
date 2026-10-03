package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var sidPattern = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)
var userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
var serviceNamePattern = regexp.MustCompile(`^Harmonia-[a-f0-9]{12}$`)

func ValidSID(sid string) bool {
	if len(sid) > 184 || !sidPattern.MatchString(sid) {
		return false
	}
	parts := strings.Split(sid, "-")
	for _, part := range parts[4:] {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return false
		}
	}
	return true
}

// ServiceConfig 仅生成待审查配置。Windows 的 UserID 是目标用户 SID，不是服务账号 SID。
type ServiceConfig struct {
	UserName       string
	UserID         string
	BinaryPath     string
	StateDirectory string
	Interval       string
	CAFile         string
}
type ServiceTemplate struct {
	Name    string
	Content []byte
}

func cleanValue(v string) bool { return v != "" && !strings.ContainsAny(v, "\x00\r\n") }
func validateUnix(c ServiceConfig) error {
	uid, err := strconv.ParseUint(c.UserID, 10, 32)
	if err != nil || uid == 0 || strconv.FormatUint(uid, 10) != c.UserID || !userPattern.MatchString(c.UserName) || c.UserName == "root" {
		return fmt.Errorf("non-root explicit local user required")
	}
	if !path.IsAbs(c.BinaryPath) || !path.IsAbs(c.StateDirectory) || !cleanValue(c.BinaryPath) || !cleanValue(c.StateDirectory) {
		return fmt.Errorf("absolute paths required")
	}
	if path.Clean(c.BinaryPath) != c.BinaryPath || path.Clean(c.StateDirectory) != c.StateDirectory {
		return fmt.Errorf("state path must be canonical")
	}
	if c.CAFile != "" && (!path.IsAbs(c.CAFile) || path.Clean(c.CAFile) != c.CAFile || !cleanValue(c.CAFile)) {
		return fmt.Errorf("CA file must be an explicit canonical absolute path")
	}
	return nil
}
func interval(c ServiceConfig) string {
	if c.Interval == "" {
		return "2s"
	}
	return c.Interval
}
func validateInterval(c ServiceConfig) error {
	if c.Interval != "" && !regexp.MustCompile(`^[1-9][0-9]*(ms|s|m)$`).MatchString(c.Interval) {
		return fmt.Errorf("invalid interval")
	}
	return nil
}
func unixArgs(c ServiceConfig) []string {
	args := []string{c.BinaryPath, "daemon", "--local-directory", c.StateDirectory, "--local-user", c.UserID, "--interval", interval(c)}
	if c.CAFile != "" {
		args = append(args, "--ca-file", c.CAFile)
	}
	return args
}
func xmlText(v string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(v))
	return b.String()
}

func LaunchDaemon(c ServiceConfig) (ServiceTemplate, error) {
	if err := validateUnix(c); err != nil {
		return ServiceTemplate{}, err
	}
	if err := validateInterval(c); err != nil {
		return ServiceTemplate{}, err
	}
	label := "org.harmonia-vault.user." + c.UserID
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n")
	fmt.Fprintf(&b, "<key>Label</key><string>%s</string>\n<key>UserName</key><string>%s</string>\n<key>ProgramArguments</key><array>\n", label, xmlText(c.UserName))
	for _, arg := range unixArgs(c) {
		fmt.Fprintf(&b, "<string>%s</string>\n", xmlText(arg))
	}
	fmt.Fprintf(&b, "</array>\n<key>WorkingDirectory</key><string>%s</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ProcessType</key><string>Background</string>\n<key>Umask</key><integer>63</integer>\n</dict></plist>\n", xmlText(c.StateDirectory))
	return ServiceTemplate{Name: label + ".plist", Content: []byte(b.String())}, nil
}
func systemdQuote(v string) string {
	v = strings.ReplaceAll(v, "%", "%%")
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return "\"" + v + "\""
}
func Systemd(c ServiceConfig) (ServiceTemplate, error) {
	if err := validateUnix(c); err != nil {
		return ServiceTemplate{}, err
	}
	if err := validateInterval(c); err != nil {
		return ServiceTemplate{}, err
	}
	if c.StateDirectory != "/var/lib/harmonia/"+c.UserID || !strings.HasPrefix(c.BinaryPath, "/usr/local/") {
		return ServiceTemplate{}, fmt.Errorf("systemd requires /var/lib/harmonia state and /usr/local binary outside ProtectHome")
	}
	args := unixArgs(c)
	for i := range args {
		args[i] = systemdQuote(args[i])
	}
	content := "[Unit]\nDescription=Harmonia 本地用户环境同步\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser=" + c.UserName + "\nUMask=0077\nExecStart=" + strings.Join(args, " ") + "\nRestart=on-failure\nRestartSec=3s\nNoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=" + systemdQuote(c.StateDirectory) + "\nWorkingDirectory=" + c.StateDirectory + "\n\n[Install]\nWantedBy=multi-user.target\n"
	return ServiceTemplate{Name: "harmonia-user-" + c.UserID + ".service", Content: []byte(content)}, nil
}

type WindowsServiceManifest struct {
	Schema         string   `json:"schema"`
	ServiceName    string   `json:"serviceName"`
	Account        string   `json:"account"`
	TargetUserSID  string   `json:"targetUserSID"`
	Executable     string   `json:"executable"`
	Arguments      []string `json:"arguments"`
	StateDirectory string   `json:"stateDirectory"`
	StartType      string   `json:"startType"`
	RequiredACL    []string `json:"requiredACL"`
	Gates          []string `json:"gates"`
}

func windowsAbsolute(v string) bool {
	return cleanValue(v) && len(v) >= 3 && ((v[0] >= 'A' && v[0] <= 'Z') || (v[0] >= 'a' && v[0] <= 'z')) && v[1] == ':' && v[2] == '\\' && !strings.Contains(v, `\..\`)
}
func WindowsService(c ServiceConfig) (ServiceTemplate, error) {
	if !ValidSID(c.UserID) || !windowsAbsolute(c.BinaryPath) || !windowsAbsolute(c.StateDirectory) {
		return ServiceTemplate{}, fmt.Errorf("explicit target SID and absolute Windows paths required")
	}
	if err := validateInterval(c); err != nil {
		return ServiceTemplate{}, err
	}
	sum := sha256.Sum256([]byte(c.UserID))
	name := "Harmonia-" + hex.EncodeToString(sum[:6])
	account := `NT SERVICE\` + name
	if c.CAFile != "" && !windowsAbsolute(c.CAFile) {
		return ServiceTemplate{}, fmt.Errorf("explicit absolute Windows CA file required")
	}
	arguments := []string{"daemon", "--local-directory", c.StateDirectory, "--local-user", c.UserID, "--windows-service", name, "--interval", interval(c)}
	if c.CAFile != "" {
		arguments = append(arguments, "--ca-file", c.CAFile)
	}
	manifest := WindowsServiceManifest{Schema: "harmonia/windows-service/v1", ServiceName: name, Account: account, TargetUserSID: c.UserID, Executable: c.BinaryPath, Arguments: arguments, StateDirectory: c.StateDirectory, StartType: "automatic", RequiredACL: []string{"服务身份只能读写本实例状态目录；其他本地用户不得访问", `只授予目标 HKEY_USERS\` + c.UserID + `\Environment 所需查询/写入权限；禁止授予其他用户 hive`, "二进制和服务配置只能由管理员写入"}, Gates: []string{"正式 Windows daemon 仍关闭；DPAPI/SID/SCM/hive 原生验收完成前不可安装或启动为可信服务", "本实现不安装服务或授予 ACL", "默认适配器在目标 hive 未加载时失败；另有未接入正式入口的受托 token profile lease 源码，无人登录 token/broker 与原生验收尚未完成", "Session 0 广播不能保证进入交互用户会话；现有进程环境不会被外部修改"}}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return ServiceTemplate{}, err
	}
	return ServiceTemplate{Name: name + ".json", Content: append(data, '\n')}, nil
}
