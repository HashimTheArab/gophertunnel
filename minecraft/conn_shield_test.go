package minecraft_test

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft"
)

func TestConnExposesShieldID(t *testing.T) {
	var _ interface{ ShieldID() int32 } = (*minecraft.Conn)(nil)
}
