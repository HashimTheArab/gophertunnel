package gatherings

import (
	"encoding/json"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/service"
)

// The gatherings environment decodes from discovery and refuses non-https endpoints.
func TestEnvironmentFromDiscovery(t *testing.T) {
	disc := func(uri string) *service.Discovery {
		return &service.Discovery{ServiceEnvironments: map[string]map[string]json.RawMessage{
			"gatherings": {"prod": json.RawMessage(`{"serviceUri":"` + uri + `"}`)},
		}}
	}
	env := new(Environment)
	if err := disc("https://gatherings.example.minecraft-services.net").Environment(env); err != nil {
		t.Fatal(err)
	}
	if env.ServiceURI.Host != "gatherings.example.minecraft-services.net" {
		t.Fatalf("ServiceURI = %v", env.ServiceURI)
	}
	for _, bad := range []string{"", "http://gatherings.example", "https://u@gatherings.example", "::"} {
		if err := disc(bad).Environment(new(Environment)); err == nil {
			t.Fatalf("%q decoded", bad)
		}
	}
}
