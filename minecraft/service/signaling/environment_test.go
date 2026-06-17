package signaling

import (
	"context"
	"encoding/json"
	"testing"
)

func TestConfigurationUnmarshalDefaultsPingFrequency(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{
			name: "zero",
			data: `{"signalingUri":"wss://example.invalid","pingFrequency":"0:0:0"}`,
		},
		{
			name: "missing",
			data: `{"signalingUri":"wss://example.invalid"}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg Configuration
			if err := json.Unmarshal([]byte(test.data), &cfg); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if cfg.PingFrequency != DefaultPingFrequency {
				t.Fatalf("PingFrequency = %v, want %v", cfg.PingFrequency, DefaultPingFrequency)
			}
		})
	}
}

func TestEnvironmentConfigurationUsesDefaultPingFrequency(t *testing.T) {
	var env Environment
	if err := json.Unmarshal([]byte(`{"serviceUri":"wss://example.invalid"}`), &env); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	cfg, err := env.Configuration(context.TODO(), nil, nil)
	if err != nil {
		t.Fatalf("Configuration() error = %v", err)
	}
	if cfg.PingFrequency != DefaultPingFrequency {
		t.Fatalf("PingFrequency = %v, want %v", cfg.PingFrequency, DefaultPingFrequency)
	}
}
