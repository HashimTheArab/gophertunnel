package room

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/df-mc/go-xsapi/v2/mpsd"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
)

func TestXBLAnnouncerPublishConfigUsesBroadcastRestrictions(t *testing.T) {
	t.Parallel()

	_, read, join := (&XBLAnnouncer{}).publishConfig(Status{BroadcastSetting: p2p.BroadcastSettingInviteOnly}, nil)
	if read != mpsd.SessionRestrictionFollowed {
		t.Fatalf("read restriction mismatch: got %q", read)
	}
	if join != mpsd.SessionRestrictionLocal {
		t.Fatalf("join restriction mismatch: got %q", join)
	}
}

func TestSyncSessionNoncesMatchesActiveMembers(t *testing.T) {
	t.Parallel()

	nonces := map[string]string{
		"200":   "existing",
		"stale": "remove-me",
	}
	generated := 0
	changed, err := syncSessionNonces(nonces, []string{"100", "200", "300", "300", ""}, "100", func() (string, error) {
		generated++
		return fmt.Sprintf("generated-%d", generated), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected nonce map to change")
	}
	if generated != 1 {
		t.Fatalf("generated %d nonces, want 1", generated)
	}
	want := map[string]string{"200": "existing", "300": "generated-1"}
	if !reflect.DeepEqual(nonces, want) {
		t.Fatalf("nonces = %v, want %v", nonces, want)
	}

	changed, err = syncSessionNonces(nonces, []string{"100", "200", "300"}, "100", func() (string, error) {
		t.Fatal("generator called for current nonce state")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("current nonce state reported as changed")
	}
}

func TestSyncSessionNoncesDoesNotMutateOnGenerationFailure(t *testing.T) {
	t.Parallel()

	nonces := map[string]string{"stale": "keep-on-failure"}
	wantErr := errors.New("random source failed")
	changed, err := syncSessionNonces(nonces, []string{"200"}, "100", func() (string, error) {
		return "", wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("syncSessionNonces() error = %v, want %v", err, wantErr)
	}
	if changed {
		t.Fatal("failed nonce generation reported a committed change")
	}
	want := map[string]string{"stale": "keep-on-failure"}
	if !reflect.DeepEqual(nonces, want) {
		t.Fatalf("nonces = %#v, want %#v", nonces, want)
	}
}

func TestXBLAnnouncerUpdateNoncesPublishesSessionStatus(t *testing.T) {
	t.Parallel()

	session := &mpsd.Session{}
	a := &XBLAnnouncer{
		Session:    session,
		nonces:     map[string]string{"stale": "remove-me"},
		lastStatus: Status{OwnerID: "100", WorldName: "World"},
	}
	var writes []json.RawMessage
	err := a.updateNonces(context.Background(), session, []string{"100", "200"}, func(_ context.Context, custom json.RawMessage) error {
		writes = append(writes, append(json.RawMessage(nil), custom...))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 {
		t.Fatalf("wrote custom properties %d times, want 1", len(writes))
	}

	var got Status
	if err := json.Unmarshal(writes[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != "100" || got.WorldName != "World" {
		t.Fatalf("published status = %+v", got)
	}
	if _, ok := got.Nonces["100"]; ok {
		t.Fatalf("owner received a nonce: %#v", got.Nonces)
	}
	if _, ok := got.Nonces["stale"]; ok {
		t.Fatalf("stale nonce was retained: %#v", got.Nonces)
	}
	if len(got.Nonces["200"]) != 16 {
		t.Fatalf("joining member nonce = %q, want 8 random bytes as hex", got.Nonces["200"])
	}

	err = a.updateNonces(context.Background(), session, []string{"100", "200"}, func(context.Context, json.RawMessage) error {
		t.Fatal("unchanged nonce state wrote custom properties")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestXBLAnnouncerUpdateNoncesIgnoresStaleSession(t *testing.T) {
	t.Parallel()

	a := &XBLAnnouncer{
		Session:    &mpsd.Session{},
		nonces:     map[string]string{},
		lastStatus: Status{OwnerID: "100"},
	}
	err := a.updateNonces(context.Background(), &mpsd.Session{}, []string{"200"}, func(context.Context, json.RawMessage) error {
		t.Fatal("stale session wrote custom properties")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.nonces) != 0 {
		t.Fatalf("stale session changed nonces: %#v", a.nonces)
	}
}

func TestXBLAnnouncerUpdateNoncesRetriesFailedPublish(t *testing.T) {
	t.Parallel()

	session := &mpsd.Session{}
	a := &XBLAnnouncer{
		Session:    session,
		nonces:     map[string]string{},
		lastStatus: Status{OwnerID: "100"},
	}
	wantErr := errors.New("publish failed")
	err := a.updateNonces(context.Background(), session, []string{"100", "200"}, func(context.Context, json.RawMessage) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("updateNonces() error = %v, want %v", err, wantErr)
	}
	if len(a.nonces) != 0 {
		t.Fatalf("failed publish committed nonce state: %#v", a.nonces)
	}

	writes := 0
	err = a.updateNonces(context.Background(), session, []string{"100", "200"}, func(context.Context, json.RawMessage) error {
		writes++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 || len(a.nonces["200"]) != 16 {
		t.Fatalf("retry writes = %d, nonces = %#v", writes, a.nonces)
	}
}

func TestXBLAnnouncerResetSessionStateClearsNonces(t *testing.T) {
	t.Parallel()

	session := &mpsd.Session{}
	a := &XBLAnnouncer{
		Session:         session,
		custom:          []byte("cached"),
		nonces:          map[string]string{"200": "stale"},
		handledSession:  session,
		readRestriction: mpsd.SessionRestrictionFollowed,
		joinRestriction: mpsd.SessionRestrictionFollowed,
	}
	a.resetSessionStateLocked()

	if a.Session != nil || a.handledSession != nil {
		t.Fatal("session references were retained")
	}
	if a.custom != nil || a.readRestriction != "" || a.joinRestriction != "" {
		t.Fatal("cached announcement state was retained")
	}
	if len(a.nonces) != 0 {
		t.Fatalf("nonce state was retained: %#v", a.nonces)
	}
}

func TestXBLAnnouncerHandlesEachPublishedSession(t *testing.T) {
	t.Parallel()

	first := &mpsd.Session{}
	second := &mpsd.Session{}
	a := &XBLAnnouncer{Session: first}
	a.handleSessionLocked()
	if a.handledSession != first {
		t.Fatal("first published session was not handled")
	}

	a.Session = second
	a.handleSessionLocked()
	if a.handledSession != second {
		t.Fatal("replacement published session was not handled")
	}
}

func TestXBLAnnouncerAnnounceHandlesUnchangedExistingSession(t *testing.T) {
	t.Parallel()

	session := &mpsd.Session{}
	status := Status{
		OwnerID:          "100",
		WorldName:        "World",
		Nonces:           map[string]string{},
		BroadcastSetting: p2p.BroadcastSettingFriendsOfFriends,
	}
	custom, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	a := &XBLAnnouncer{
		Session:         session,
		custom:          custom,
		nonces:          map[string]string{},
		readRestriction: mpsd.SessionRestrictionFollowed,
		joinRestriction: mpsd.SessionRestrictionFollowed,
	}
	if err := a.Announce(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	if a.handledSession != session {
		t.Fatal("unchanged existing session was not registered for member changes")
	}
	if a.lastStatus.OwnerID != "100" || a.lastStatus.WorldName != "World" {
		t.Fatalf("last status = %+v", a.lastStatus)
	}
}
