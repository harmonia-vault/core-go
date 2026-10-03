package linuxinstall

import "testing"

func TestOfflineCompletionRequiresFinalVersionedExactResult(t *testing.T) {
	if decodeLocalCompletion([]byte(`{"version":1,"localLogoutComplete":true}`)) != nil {
		t.Fatal("mature completion DTO rejected")
	}
	for _, c := range []struct{ name, value string }{
		{"false", `{"version":1,"localLogoutComplete":false}`}, {"unknownVersion", `{"version":2,"localLogoutComplete":true}`}, {"trustedShortcut", `{"version":1,"trusted":true}`}, {"unknown", `{"version":1,"localLogoutComplete":true,"state":{}}`}, {"duplicate", `{"version":1,"localLogoutComplete":true,"localLogoutComplete":false}`}, {"trailer", `{"version":1,"localLogoutComplete":true} {}`}, {"progressInsteadOfResult", `{"stage":"slots_removed"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if decodeLocalCompletion([]byte(c.value)) != ErrState {
				t.Fatal("non-final completion falsely accepted")
			}
		})
	}
}
