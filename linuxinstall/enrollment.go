package linuxinstall

type enrollmentCompletion struct {
	Version  int  `json:"version"`
	Verified bool `json:"localEnrollmentVerified"`
}

func decodeEnrollmentCompletion(data []byte) error {
	var r enrollmentCompletion
	if len(data) > maxLocalCompletionBytes || decodeRecord(data, &r) != nil || r.Version != 1 || !r.Verified {
		return ErrState
	}
	return nil
}
