package minecraft

import (
	"errors"
	"fmt"
	"net"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func (p *PreparedDial) listen() {
	conn := p.conn
	closeCause := error(net.ErrClosed)
	defer func() {
		_ = conn.close(closeCause)
		close(p.listenerDone)
	}()
	connected, cancelContext := p.connected, true
	for {
		callbackErr := false
		if err := conn.dec.DecodeFunc(func(data []byte) error {
			if !p.live.Load() {
				p.mu.Lock()
				if !p.live.Load() {
					err := p.receiveBeforeLogin(data)
					p.mu.Unlock()
					callbackErr = err != nil
					return err
				}
				p.mu.Unlock()
			}
			loggedInBefore, handshakeCompleteBefore, passthroughReadyBefore := conn.loggedIn, conn.handshakeComplete, conn.disablePacketHandlingReady
			if err := conn.receive(data); err != nil {
				callbackErr = true
				return err
			}
			if ((!handshakeCompleteBefore && conn.handshakeComplete) || (!passthroughReadyBefore && conn.disablePacketHandlingReady)) && conn.disablePacketHandling && connected != nil {
				close(connected)
				connected = nil
			}
			if !loggedInBefore && conn.loggedIn {
				if connected != nil {
					close(connected)
					connected = nil
				}
				cancelContext = false
			}
			return nil
		}); err != nil {
			p.flushBatch()
			if callbackErr || !errors.Is(err, net.ErrClosed) {
				if cancelContext {
					closeCause = err
					p.cancel(err)
				} else {
					conn.log.Error(err.Error())
				}
			}
			return
		}
		p.flushBatch()
	}
}

func (p *PreparedDial) flushBatch() {
	if !p.live.Load() {
		p.mu.Lock()
		defer p.mu.Unlock()
	}
	p.conn.flushBatch()
}

// Before Login, only settings and terminal connection control may affect state.
func (p *PreparedDial) receiveBeforeLogin(data []byte) error {
	conn := p.conn
	pkData, err := parseData(data, conn)
	if err != nil {
		return err
	}
	pks, err := pkData.decode(conn)
	if err != nil {
		return err
	}
	if err := preLoginTransferError(pks); err != nil {
		return err
	}
	for _, pk := range pks {
		switch pk := pk.(type) {
		case *packet.NetworkSettings:
			if !conn.readyToLogin {
				if err := conn.handleNetworkSettings(pk); err != nil {
					return err
				}
				close(p.settingsReady)
			}
		case *packet.Disconnect:
			return conn.wrap(&DisconnectPacketError{
				Reason: pk.Reason, HideDisconnectionScreen: pk.HideDisconnectionScreen,
				Message: pk.Message, FilteredMessage: pk.FilteredMessage,
				DisplayMessage: conn.disconnectPacketMessage(pk),
			}, "prepare")
		case *packet.PlayStatus:
			if pk.Status != packet.PlayStatusLoginSuccess && pk.Status != packet.PlayStatusPlayerSpawn {
				return fmt.Errorf("prepared login rejected: %w", conn.handlePlayStatus(pk))
			}
		}
	}
	return nil
}
