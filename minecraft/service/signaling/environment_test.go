package signaling

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfigurationUnmarshalDefaultsZeroPingFrequency(t *testing.T) {
	var cfg Configuration
	if err := json.Unmarshal([]byte(`{"signalingUri":"wss://example.invalid","pingFrequency":"0:0:0"}`), &cfg); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if cfg.PingFrequency != 15*time.Second {
		t.Fatalf("PingFrequency = %v, want 15s", cfg.PingFrequency)
	}
}
