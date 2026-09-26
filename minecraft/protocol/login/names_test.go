package login

import (
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// TestFallbackDisplayName checks ordinary, Nintendo, and trusted-host name rules.
func TestFallbackDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		device  protocol.DeviceOS
		host    bool
		want    string
		wantErr bool
	}{
		{name: "ordinary", input: "Steve", want: "Steve"},
		{name: "digits", input: "1234", want: "1234"},
		{name: "underscores", input: "____", want: "____"},
		{name: "punctuation", input: "O'Brien-(2)", want: "O'Brien-(2)"},
		{name: "spaces", input: " A  B ", want: " A  B "},
		{name: "sixteen ASCII characters", input: strings.Repeat("a", 16), want: strings.Repeat("a", 16)},
		{name: "sixteen Unicode characters", input: strings.Repeat("é", 16), want: strings.Repeat("é", 16)},
		{name: "seventeen characters", input: strings.Repeat("é", 17), wantErr: true},
		{name: "empty", wantErr: true},
		{name: "only spaces", input: "   ", wantErr: true},
		{name: "only whitespace", input: " \t\n\r", wantErr: true},
		{name: "embedded newline", input: "A\nB", wantErr: true},
		{name: "embedded NUL", input: "A\x00B", wantErr: true},
		{name: "at sign", input: "A@B", wantErr: true},
		{name: "emoji", input: "A😀", wantErr: true},
		{name: "multiplication sign", input: "×", want: "×"},
		{name: "division sign", input: "÷", wantErr: true},
		{name: "Latin range end", input: "ſ", want: "ſ"},
		{name: "Latin range excluded neighbor", input: "ƀ", wantErr: true},
		{name: "Hebrew", input: "שלום", want: "שלום"},
		{name: "Arabic", input: "مرحبا", want: "مرحبا"},
		{name: "CJK", input: "世界", want: "世界"},
		{name: "Hangul", input: "안녕", want: "안녕"},
		{name: "Katakana last allowed", input: "ヺ", want: "ヺ"},
		{name: "Katakana middle dot", input: "・", wantErr: true},
		{name: "Katakana long vowel", input: "ー", wantErr: true},
		{name: "invalid UTF-8", input: "A\xffB", wantErr: true},
		{name: "incomplete UTF-8", input: "A\xc3", wantErr: true},
		{name: "Nintendo ordinary", input: "Steve", device: protocol.DeviceNX, want: "Steve"},
		{name: "Nintendo extra punctuation", input: "[]!$&*+,./:;<=>?", device: protocol.DeviceNX, want: "[]!$&*+,./:;<=>?"},
		{name: "Nintendo at sign", input: "A@B", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo percent", input: "A%B", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo backslash", input: "A\\B", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo filter", input: "A\"§B", device: protocol.DeviceNX, want: "AB"},
		{name: "Nintendo filtered empty", input: "\"§", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo space after filtering", input: "\" \"", device: protocol.DeviceNX, want: " "},
		{name: "Nintendo initial whitespace", input: "   ", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo ideographic space", input: "\u3000", device: protocol.DeviceNX, want: "\u3000"},
		{name: "Nintendo division sign", input: "÷", device: protocol.DeviceNX, want: "÷"},
		{name: "Nintendo symbols", input: "ƒǅǆǲǳȚțˇ˘˙˛˜", device: protocol.DeviceNX, want: "ƒǅǆǲǳȚțˇ˘˙˛˜"},
		{name: "Nintendo symbol gap", input: "Ǆ", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo arrows", input: "←↑→↓⇒⇔∀∂√∞∴∵⌒", device: protocol.DeviceNX, want: "←↑→↓⇒⇔∀∂√∞∴∵⌒"},
		{name: "Nintendo arrow gap", input: "↔", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo shapes", input: "■□▲△▼▽◆◇○◎●★☆♀♂♪", device: protocol.DeviceNX, want: "■□▲△▼▽◆◇○◎●★☆♀♂♪"},
		{name: "Nintendo shape gap", input: "▢", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo Japanese punctuation", input: "ゝゞ・ー！？，", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo Japanese additions", input: "ゝゞ・ー！？～", device: protocol.DeviceNX, want: "ゝゞ・ー！？～"},
		{name: "Nintendo seventeen filtered characters", input: strings.Repeat("\"", 16) + "A", device: protocol.DeviceNX, wantErr: true},
		{name: "Nintendo invalid UTF-8", input: "A\xffB", device: protocol.DeviceNX, wantErr: true},
		{name: "host whitespace", input: " \t\n\r", host: true, want: " \t\n\r"},
		{name: "host punctuation and emoji", input: "A@B😀", host: true, want: "A@B😀"},
		{name: "host NUL", input: "\x00", host: true, want: "\x00"},
		{name: "host filter", input: "A\"§B", host: true, want: "AB"},
		{name: "host empty", host: true, wantErr: true},
		{name: "host filtered empty", input: "\"§", host: true, wantErr: true},
		{name: "host truncation", input: strings.Repeat("é", 17), host: true, want: strings.Repeat("é", 16)},
		{name: "host filtered input budget", input: strings.Repeat("\"", 15) + "AB", host: true, want: "A"},
		{name: "host exhausted filtered budget", input: strings.Repeat("\"", 16) + "A", host: true, wantErr: true},
		{name: "host invalid prefix", input: "\xffA", host: true, wantErr: true},
		{name: "host invalid suffix", input: "A\xffB", host: true, want: "A"},
		{name: "host incomplete suffix", input: "A\xc3", host: true, want: "A"},
		{name: "host overlong UTF-8", input: "A\xc0\xafB", host: true, want: "A"},
		{name: "host surrogate", input: "A\xed\xa0\x80B", host: true, want: "A"},
		{name: "host replacement character", input: "A\ufffdB", host: true, want: "A\ufffdB"},
		{name: "host noncharacter range start", input: "A\ufdd0B", host: true, want: "A"},
		{name: "host noncharacter range end", input: "A\ufdefB", host: true, want: "A"},
		{name: "host noncharacter range neighbors", input: "A\ufdcf\ufdf0B", host: true, want: "A\ufdcf\ufdf0B"},
		{name: "host BMP noncharacter", input: "A\ufffeB", host: true, want: "A"},
		{name: "host supplementary noncharacter", input: "A\U0001ffffB", host: true, want: "A"},
		{name: "host final noncharacter", input: "A\U0010ffffB", host: true, want: "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fallbackDisplayName(tt.input, tt.device, tt.host)
			if (err != nil) != tt.wantErr {
				t.Fatalf("fallbackDisplayName(%q) error = %v, want error %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("fallbackDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
