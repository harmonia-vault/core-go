package linuxinstall

const maxLocalCompletionBytes = 4096

type localLogoutResult struct {
	Version             int  `json:"version"`
	LocalLogoutComplete bool `json:"localLogoutComplete"`
}

func decodeLocalCompletion(data []byte) error {
	var result localLogoutResult
	if len(data) > maxLocalCompletionBytes || decodeRecord(data, &result) != nil || result.Version != 1 || !result.LocalLogoutComplete {
		return ErrState
	}
	return nil
}
