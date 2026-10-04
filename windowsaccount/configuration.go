package windowsaccount

type Configuration struct {
	Schema string `json:"schema"`
	Plan   Plan   `json:"plan"`
	CAFile string `json:"caFile,omitempty"`
}

func (c Configuration) Validate() error {
	if c.Schema != "harmonia/windows-account-service/v1" || c.Plan.Validate() != nil {
		return ErrPlan
	}
	if c.CAFile != "" && c.CAFile != c.Plan.InstallDirectory()+`\ca.pem` {
		return ErrPlan
	}
	return nil
}
