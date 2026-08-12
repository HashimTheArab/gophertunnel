package room

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"time"

	"github.com/df-mc/go-xsapi/v2/mpsd"
)

func (a *XBLAnnouncer) marshalStatusLocked(status Status) ([]byte, error) {
	return marshalStatusWithNonces(status, a.nonces)
}

func marshalStatusWithNonces(status Status, nonces map[string]string) ([]byte, error) {
	status.Nonces = maps.Clone(nonces)
	if status.Nonces == nil {
		status.Nonces = map[string]string{}
	}
	return json.Marshal(status)
}

func (a *XBLAnnouncer) updateNonces(ctx context.Context, session *mpsd.Session, activeXUIDs []string, setCustomProperties func(context.Context, json.RawMessage) error) error {
	a.Lock()
	defer a.Unlock()
	if session != a.Session {
		return nil
	}
	nonces := maps.Clone(a.nonces)
	if nonces == nil {
		nonces = map[string]string{}
	}
	changed, err := syncSessionNonces(nonces, activeXUIDs, a.lastStatus.OwnerID, generateSessionNonce)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	custom, err := marshalStatusWithNonces(a.lastStatus, nonces)
	if err != nil {
		return fmt.Errorf("room: encode status with session nonces: %w", err)
	}
	if err := setCustomProperties(ctx, custom); err != nil {
		return fmt.Errorf("room: set custom properties with session nonces: %w", err)
	}
	a.nonces = nonces
	a.custom = custom
	return nil
}

func (a *XBLAnnouncer) resetSessionStateLocked() {
	a.Session = nil
	a.handledSession = nil
	a.custom = nil
	a.readRestriction = ""
	a.joinRestriction = ""
	a.nonces = make(map[string]string)
}

func (a *XBLAnnouncer) handleSessionLocked() {
	if a.Session == nil || a.Session == a.handledSession {
		return
	}
	a.handledSession = a.Session
	a.Session.Handle(xblNonceHandler{announcer: a})
}

type xblNonceHandler struct {
	announcer *XBLAnnouncer
}

func (h xblNonceHandler) HandleSessionChange(session *mpsd.Session) {
	ctx, cancel := context.WithTimeout(session.Context(), 15*time.Second)
	defer cancel()
	setCustomProperties := func(ctx context.Context, custom json.RawMessage) error {
		return session.SetCustomProperties(ctx, custom)
	}
	if err := h.announcer.updateNonces(ctx, session, sessionMemberXUIDs(session), setCustomProperties); err != nil {
		log := h.announcer.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("update MPSD session nonces", slog.Any("error", err))
	}
}

func sessionMemberXUIDs(session *mpsd.Session) []string {
	var xuids []string
	for _, member := range session.Members() {
		if member.Constants == nil || member.Constants.System == nil {
			continue
		}
		xuid := strings.TrimSpace(member.Constants.System.XUID)
		if xuid != "" {
			xuids = append(xuids, xuid)
		}
	}
	return xuids
}

func syncSessionNonces(nonces map[string]string, activeXUIDs []string, ownerXUID string, generate func() (string, error)) (bool, error) {
	if nonces == nil {
		return false, errors.New("room: nonces map is nil")
	}
	if generate == nil {
		generate = generateSessionNonce
	}
	ownerXUID = strings.TrimSpace(ownerXUID)
	active := make(map[string]struct{}, len(activeXUIDs))
	for _, xuid := range activeXUIDs {
		xuid = strings.TrimSpace(xuid)
		if xuid == "" || xuid == ownerXUID {
			continue
		}
		active[xuid] = struct{}{}
	}

	next := maps.Clone(nonces)
	changed := false
	for xuid := range next {
		if _, ok := active[xuid]; !ok {
			delete(next, xuid)
			changed = true
		}
	}
	for xuid := range active {
		if _, ok := next[xuid]; ok {
			continue
		}
		nonce, err := generate()
		if err != nil {
			return false, err
		}
		next[xuid] = nonce
		changed = true
	}
	if changed {
		clear(nonces)
		maps.Copy(nonces, next)
	}
	return changed, nil
}

func generateSessionNonce() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
