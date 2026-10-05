package windowsservice

import (
	"encoding/xml"
	"strings"
)

const taskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"

// TaskXML 仅生成可审阅配置，不注册 task、不授予 Batch 权限。
func (c Config) TaskXML() (string, error) {
	if e := c.Validate(); e != nil {
		return "", e
	}
	escape := func(s string) string { var b strings.Builder; _ = xml.EscapeText(&b, []byte(s)); return b.String() }
	return `<?xml version="1.0"?><Task version="1.4" xmlns="` + taskNamespace + `"><Principals><Principal id="Target"><UserId>` + escape(c.TargetSID) + `</UserId><LogonType>S4U</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT30S</ExecutionTimeLimit></Settings><Actions Context="Target"><Exec><Command>` + escape(c.Executable) + `</Command><Arguments>` + escape(c.taskArguments()) + `</Arguments></Exec></Actions></Task>`, nil
}

type taskDefinition struct {
	XMLName    xml.Name
	Principals []struct {
		UserID    string `xml:"UserId"`
		GroupID   string `xml:"GroupId"`
		LogonType string
		RunLevel  string
	} `xml:"Principals>Principal"`
	Actions []struct {
		XMLName          xml.Name
		Command          string
		Arguments        string
		WorkingDirectory string
	} `xml:"Actions>Exec"`
	Com      []struct{} `xml:"Actions>ComHandler"`
	Emails   []struct{} `xml:"Actions>SendEmail"`
	Messages []struct{} `xml:"Actions>ShowMessage"`
	Settings struct {
		Enabled            string
		AllowStartOnDemand string
		ExecutionTimeLimit string
	}
}

// ValidateTask 拒绝改动的 target/action，不接受任务参数替换、其它动作或 interactive token。
func (c Config) ValidateTask(data []byte) error {
	if c.Validate() != nil || len(data) == 0 || len(data) > 64<<10 {
		return ErrConfiguration
	}
	var d taskDefinition
	if xml.Unmarshal(data, &d) != nil || d.XMLName.Local != "Task" || d.XMLName.Space != taskNamespace || len(d.Principals) != 1 || len(d.Actions) != 1 || len(d.Com)+len(d.Emails)+len(d.Messages) != 0 {
		return ErrConfiguration
	}
	p := d.Principals[0]
	a := d.Actions[0]
	if p.UserID != c.TargetSID || p.GroupID != "" || p.LogonType != "S4U" || p.RunLevel != "LeastPrivilege" || a.Command != c.Executable || a.Arguments != c.taskArguments() || a.WorkingDirectory != "" || d.Settings.Enabled != "true" || d.Settings.AllowStartOnDemand != "true" || d.Settings.ExecutionTimeLimit != "PT30S" {
		return ErrConfiguration
	}
	return nil
}
