package text

import "testing"

func TestCodes_IncludesEveryCode(t *testing.T) {
	codes := map[string]bool{}
	for _, code := range Codes() {
		codes[code] = true
	}
	for _, want := range []string{Black, White, Resin, PartyBlue, Obfuscated, Bold, Italic, Reset} {
		if !codes[want] {
			t.Errorf("Codes() is missing %q", want)
		}
	}
	for _, entry := range append(Colors(), FormattingCodes()...) {
		if !codes[entry.Code] {
			t.Errorf("Codes() is missing %s (%q)", entry.Name, entry.Code)
		}
	}
}
