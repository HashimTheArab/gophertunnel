package login

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// fallbackDisplayName validates the client name when no trusted platform name is available.
func fallbackDisplayName(name string, deviceOS protocol.DeviceOS, trustedHost bool) (string, error) {
	if trustedHost {
		name = sanitizeDisplayName(name)
	} else {
		if strings.Trim(name, " \t\n\r") == "" {
			return "", fmt.Errorf("ThirdPartyName must not be empty or contain only whitespace")
		}
		remaining := name
		for count := 0; len(remaining) != 0; count++ {
			if count == 16 {
				return "", fmt.Errorf("ThirdPartyName must not be longer than 16 characters")
			}
			r, size := displayNameRune(remaining)
			if size == 0 {
				return "", fmt.Errorf("ThirdPartyName contains invalid text")
			}
			if !ordinaryDisplayNameCharacter(r) && (deviceOS != protocol.DeviceNX || !nintendoDisplayNameCharacter(r)) {
				return "", fmt.Errorf("ThirdPartyName contains an invalid character: %U", r)
			}
			remaining = remaining[size:]
		}
		if deviceOS == protocol.DeviceNX {
			name = sanitizeDisplayName(name)
		}
	}
	if name == "" {
		return "", fmt.Errorf("ThirdPartyName must not be empty after filtering")
	}
	return name, nil
}

// displayNameRune decodes one character, rejecting invalid UTF-8 and Unicode noncharacters.
func displayNameRune(s string) (rune, int) {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size == 1 || r >= 0xfdd0 && r <= 0xfdef || r&0xfffe == 0xfffe {
		return 0, 0
	}
	return r, size
}

// sanitizeDisplayName filters the first 16 input characters and stops at invalid text.
func sanitizeDisplayName(name string) string {
	var result strings.Builder
	for count := 0; count < 16 && len(name) != 0; count++ {
		r, size := displayNameRune(name)
		if size == 0 {
			break
		}
		if r != '"' && r != '§' {
			result.WriteString(name[:size])
		}
		name = name[size:]
	}
	return result.String()
}

// ordinaryDisplayNameCharacter reports whether a character is allowed in a 1.26.30 client name.
func ordinaryDisplayNameCharacter(r rune) bool {
	switch r {
	case ' ', '\'', '(', ')', '-', '_':
		return true
	}
	switch {
	case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z',
		r >= 0x00c0 && r <= 0x00f6, r >= 0x00f8 && r <= 0x017f,
		r >= 0x0390 && r <= 0x03ce, r >= 0x0400 && r <= 0x045f,
		r >= 0x05d0 && r <= 0x05ea, r >= 0x0620 && r <= 0x064a,
		r >= 0x0660 && r <= 0x0669, r >= 0x0671 && r <= 0x06d3,
		r >= 0x06f0 && r <= 0x06f9, r >= 0x0900 && r <= 0x094f,
		r >= 0x0966 && r <= 0x096f, r >= 0x0985 && r <= 0x09b9,
		r >= 0x0e01 && r <= 0x0e3a, r >= 0x0e40 && r <= 0x0e4e,
		r >= 0x1100 && r <= 0x1112, r >= 0x1161 && r <= 0x1175,
		r >= 0x11a8 && r <= 0x11c2, r >= 0x3041 && r <= 0x3096,
		r >= 0x30a1 && r <= 0x30fa, r >= 0x4e00 && r <= 0x9fff,
		r >= 0xac00 && r <= 0xd7a3:
		return true
	}
	return false
}

// nintendoDisplayNameCharacter reports whether a character is allowed in addition to ordinary names.
func nintendoDisplayNameCharacter(r rune) bool {
	switch {
	case r >= 0x0020 && r <= 0x0024, r >= 0x0026 && r <= 0x002f,
		r >= 0x003a && r <= 0x003f, r >= 0x005d && r <= 0x0060,
		r >= 0x007b && r <= 0x007e, r >= 0x00a1 && r <= 0x00ac,
		r >= 0x00ae && r <= 0x00bf, r >= 0x0384 && r <= 0x038a,
		r >= 0x2039 && r <= 0x203b, r >= 0x2190 && r <= 0x2193,
		r >= 0x2282 && r <= 0x2283, r >= 0x3000 && r <= 0x3003,
		r >= 0x309d && r <= 0x309e, r >= 0x30fb && r <= 0x30fc:
		return true
	}
	switch r {
	case 0x005b, 0x00f7, 0x0192, 0x01c5, 0x01c6, 0x01f2, 0x01f3, 0x021a, 0x021b,
		0x02c7, 0x02d8, 0x02d9, 0x02db, 0x02dc, 0x037e, 0x038c, 0x038e, 0x038f,
		0x2013, 0x2014, 0x2018, 0x2019, 0x201a, 0x201b, 0x201c, 0x201d, 0x201e,
		0x2020, 0x2021, 0x2022, 0x2026, 0x2030, 0x2032, 0x2033, 0x20ac, 0x2116, 0x2122,
		0x21d2, 0x21d4, 0x2200, 0x2202, 0x221a, 0x221e, 0x2234, 0x2235, 0x2312,
		0x25a0, 0x25a1, 0x25b2, 0x25b3, 0x25bc, 0x25bd, 0x25c6, 0x25c7, 0x25cb, 0x25ce, 0x25cf,
		0x2605, 0x2606, 0x2640, 0x2642, 0x266a, 0x266d, 0x3005, 0x3006,
		0x300c, 0x300d, 0x300e, 0x300f, 0x3010, 0x3011, 0x3012, 0x4edd, 0xff01, 0xff1f, 0xff5e:
		return true
	}
	return false
}
