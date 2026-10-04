package windowsaccount

import "testing"

func TestDispatcherNameAcceptsOnlyCanonicalFixedLayout(t *testing.T) {
	const good = `C:\Program Files\Harmonia\HarmoniaUser-41e81daa5894\service.json`
	name, err := DispatcherName(good)
	if err != nil || name != "HarmoniaUser-41e81daa5894" {
		t.Fatal("canonical routing name rejected")
	}
	for _, path := range []string{
		`c:\Program Files\Harmonia\HarmoniaUser-41e81daa5894\service.json`,
		`C:\Program Files\Harmonia\..\HarmoniaUser-41e81daa5894\service.json`,
		`C:\Program Files\Harmonia\HarmoniaUser-41e81daa5894\service.json:stream`,
		`\\host\share\HarmoniaUser-41e81daa5894\service.json`,
		`C:\Program Files\Harmonia\HarmoniaUser-41e81daa5894a\service.json`,
		good + "\x00", good + "\n", good + `\other`,
	} {
		if name, err := DispatcherName(path); err == nil || name != "" {
			t.Fatal("noncanonical routing path accepted")
		}
	}
	if sharedParentMetadataMask != 0x200a0 {
		t.Fatal("shared parent metadata mask widened")
	}
}
