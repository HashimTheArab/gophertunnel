package auth

import "testing"

// XAS and SISU requests must name the XAL build the game ships, or they look like an outdated client.
func TestConfigsUseShippedXALBuild(t *testing.T) {
	for name, tc := range map[string]struct{ got, want string }{
		"Android": {AndroidConfig.UserAgent, "XAL Android 2025.11.20251111.000"},
		"iOS":     {IOSConfig.UserAgent, "XAL iOS 2025.11.20251111.000"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s UserAgent = %q, want %q", name, tc.got, tc.want)
		}
	}
}
