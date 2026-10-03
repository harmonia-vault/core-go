package mobilebridge

import (
	"context"
	"github.com/harmonia-vault/core-go/syncclient"
	"strconv"
)

var managementFields = map[string][]string{
	"managementDevices":            {"environmentId"},
	"prepareDeviceGrant":           {"environmentId", "subjectDeviceId", "role", "expiresAt", "id"},
	"prepareOtherDeviceRevocation": {"environmentId", "subjectDeviceId", "id"},
	"managementInfo":               {}, "retryManagement": {"id"}, "cancelManagement": {"id"},
}

func managementOperation(op string) bool { _, ok := managementFields[op]; return ok }
func (v *VaultWorkflow) executeManagement(ctx context.Context, c workflowCommand) (any, error) {
	f := c.fields
	switch c.operation {
	case "managementDevices":
		return v.workflow.ManagementDevices(ctx, f["environmentId"])
	case "prepareDeviceGrant":
		expiry, err := strconv.ParseInt(f["expiresAt"], 10, 64)
		if err != nil || expiry < 0 || strconv.FormatInt(expiry, 10) != f["expiresAt"] || (f["role"] != "ro" && f["role"] != "rw" && f["role"] != "admin" && f["role"] != "none") || f["role"] == "none" && expiry != 0 {
			return nil, errInput
		}
		return v.workflow.PrepareDeviceGrant(ctx, syncclient.GrantUpdateIntent{ID: f["id"], EnvironmentID: f["environmentId"], SubjectDeviceID: f["subjectDeviceId"], Role: f["role"], ExpiresAt: expiry})
	case "prepareOtherDeviceRevocation":
		return v.workflow.PrepareOtherDeviceRevocation(ctx, f["id"], f["subjectDeviceId"], f["environmentId"])
	case "managementInfo":
		return v.workflow.ManagementInfo()
	case "cancelManagement":
		return nil, v.workflow.CancelManagement(f["id"])
	case "retryManagement":
		result, err := v.workflow.RetryManagement(ctx, f["id"])
		// 已接受元数据可返回；任何错误都不得声称末次原生密封已完成或出业务值。
		if err != nil {
			result.Applied = false
		}
		return result, err
	}
	return nil, errInput
}
