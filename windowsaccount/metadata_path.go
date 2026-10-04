package windowsaccount

import "strings"

// metadataNTPath accepts only canonical local DOS drive paths. It cannot select
// a UNC/device namespace, alternate stream, relative path or dot component.
func metadataNTPath(path string) (string, error) {
	if len(path) < 3 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` {
		return "", ErrPlan
	}
	if strings.ContainsAny(path[3:], "/:\x00<>\"|?*") {
		return "", ErrPlan
	}
	for _, c := range path {
		if c < 32 {
			return "", ErrPlan
		}
	}
	if len(path) > 3 {
		for _, part := range strings.Split(path[3:], `\`) {
			if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
				return "", ErrPlan
			}
		}
	}
	return `\??\` + path, nil
}
