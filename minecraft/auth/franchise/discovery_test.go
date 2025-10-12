package franchise

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/auth/authclient"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestDiscover(t *testing.T) {
	d, err := Discover(t.Context(), authclient.DefaultClient, protocol.CurrentVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", d)

	a := new(AuthorizationEnvironment)
	if err := d.Environment(a, EnvironmentTypeProduction); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", a)
}
