package windowsaccount

import (
	"slices"
	"sort"
)

type InstallRequest struct {
	Configuration Configuration `json:"configuration"`
	BinarySource  string        `json:"binarySource"`
	BinarySHA256  string        `json:"binarySha256"`
	CASource      string        `json:"caSource,omitempty"`
	CASHA256      string        `json:"caSha256,omitempty"`
}
type Receipt struct {
	Schema             string            `json:"schema"`
	Configuration      Configuration     `json:"configuration"`
	Stage              string            `json:"stage"`
	Pending            string            `json:"pending,omitempty"`
	DirectRightsBefore []string          `json:"directRightsBefore"`
	AddedServiceRight  bool              `json:"addedServiceRight"`
	ServiceCreated     bool              `json:"serviceCreated"`
	LastCreate         *CreateResult     `json:"lastCreate,omitempty"`
	LastStart          *StartResult      `json:"lastStart,omitempty"`
	Files              map[string]string `json:"files"`
}

func rightAdditionMatches(before, after []string) bool {
	expected := slices.Clone(before)
	if !hasNamedRight(expected, ServiceLogonRight) {
		expected = append(expected, ServiceLogonRight)
	}
	sort.Strings(expected)
	actual := slices.Clone(after)
	sort.Strings(actual)
	return slices.Equal(expected, actual)
}
func rightRemovalMatches(before, after []string) bool {
	expected := []string{}
	for _, r := range before {
		if r != ServiceLogonRight {
			expected = append(expected, r)
		}
	}
	sort.Strings(expected)
	actual := slices.Clone(after)
	sort.Strings(actual)
	return slices.Equal(expected, actual)
}
func hasNamedRight(rights []string, name string) bool {
	for _, r := range rights {
		if r == name {
			return true
		}
	}
	return false
}

// 权限变化不能顺带删除Deny或任何既有账号权利。
func rightShouldBeAdded(direct []string, effectiveAllow, effectiveDeny bool) (bool, error) {
	if effectiveDeny || hasNamedRight(direct, DenyServiceLogonRight) {
		return false, ErrIdentity
	}
	return !effectiveAllow && !hasNamedRight(direct, ServiceLogonRight), nil
}

// 停止是先前启动/停止结果不明时的安全收敛路径；不借此跳过安装前置步骤。
func mayStopReceipt(r Receipt) bool {
	if r.Stage != "installed-disabled" && r.Stage != "running-automatic" && r.Stage != "stopped-disabled" {
		return false
	}
	return r.Pending == "" || r.Pending == "start-service" || r.Pending == "enable-automatic" || r.Pending == "disable-and-drain"
}
