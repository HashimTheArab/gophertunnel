package room

import (
	"testing"

	"github.com/df-mc/go-xsapi/v2/mpsd"
)

func TestXBLAnnouncerInviteOnlyRestrictions(t *testing.T) {
	t.Parallel()

	read, join := (&XBLAnnouncer{}).restrictions(BroadcastSettingInviteOnly)
	if read != mpsd.SessionRestrictionFollowed {
		t.Fatalf("read restriction mismatch: got %q", read)
	}
	if join != mpsd.SessionRestrictionLocal {
		t.Fatalf("join restriction mismatch: got %q", join)
	}
}
