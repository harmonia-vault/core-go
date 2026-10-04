package windowsaccount

import "regexp"

var dispatcherConfigurationPath = regexp.MustCompile(`^C:\\Program Files\\Harmonia\\(HarmoniaUser-[0-9a-f]{12})\\service\.json$`)

// DispatcherName routes the initial SCM connection only; it grants no trust in
// the path or its contents. The handler must still LoadConfiguration and verify
// the process identity, service SID and exact plan before opening local keys.
func DispatcherName(configPath string) (string, error) {
	m := dispatcherConfigurationPath.FindStringSubmatch(configPath)
	if len(m) != 2 {
		return "", ErrPlan
	}
	return m[1], nil
}
