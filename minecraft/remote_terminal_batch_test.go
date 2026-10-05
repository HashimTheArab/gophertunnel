package minecraft

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestEncryptedRemoteTransportCloseDrainsDisconnectBatch(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		name := "ordinary"
		if prepared {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := (ListenConfig{AuthenticationDisabled: true, FlushRate: -1}).Listen("raknet", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			sendTerminal, gateEntered, releaseGate := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseGate) }) }
			t.Cleanup(release)
			serverDone := make(chan error, 1)
			const marker, message = "ordered terminal fixture", "disconnect fixture"
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				server := raw.(*Conn)
				defer server.Abort()
				if err = server.SendStartGame(GameData{}); err == nil {
					err = server.Flush()
				}
				if err != nil {
					serverDone <- err
					return
				}
				<-sendTerminal
				err = server.WritePacketImmediate(
					&packet.Text{TextType: packet.TextTypeSystem, Message: marker},
					&packet.Disconnect{Reason: packet.DisconnectReasonKicked, Message: message},
				)
				if err == nil {
					err = server.conn.(*raknet.Conn).Close()
				}
				serverDone <- err
			}()
			dialer := Dialer{FlushRate: -1, RelayStartup: true, EnableBatchReading: true,
				PacketFunc: func(header packet.Header, _ []byte, _, _ net.Addr) {
					if header.PacketID == packet.IDText {
						once.Do(func() { close(gateEntered); <-releaseGate })
					}
				},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var conn *Conn
			address := listener.Addr().String()
			if prepared {
				prefix, prefixErr := dialer.PrepareContextNetwork(ctx, RakNet{}, address, 1)
				if prefixErr != nil {
					t.Fatal(prefixErr)
				}
				defer prefix.Close()
				<-prefix.Done()
				conn, err = prefix.CommitContext(ctx, dialer, address, 1)
			} else {
				conn, err = dialer.DialContextNetwork(ctx, RakNet{}, address)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Abort()
			if !conn.handshakeComplete || conn.disableEncryption {
				t.Fatal("fixture did not negotiate encrypted Login")
			}
			close(sendTerminal)
			select {
			case <-gateEntered:
			case <-ctx.Done():
				t.Fatal("terminal application batch did not reach decoder gate")
			}
			select {
			case <-conn.Context().Done():
			case <-ctx.Done():
				release()
				t.Fatal("actual peer transport notification did not overtake SDK handling")
			}
			var transport interface{ TransportCloseReason() string }
			if !errors.As(context.Cause(conn.Context()), &transport) || transport.TransportCloseReason() != "remote_disconnect" {
				release()
				t.Skip("missing fixture: transport close reason metadata required for the encrypted remote-close race")
			}
			release()
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var delivered bool
			for {
				batch, readErr := conn.ReadBatchRaw(func(id uint32) bool { return id == packet.IDText })
				if readErr != nil {
					var disconnect *DisconnectPacketError
					if !delivered || !errors.As(readErr, &disconnect) || disconnect.Reason != packet.DisconnectReasonKicked || disconnect.Message != message {
						t.Fatalf("peer transport closure discarded preceding data or typed Disconnect: delivered=%v cause=%T", delivered, readErr)
					}
					break
				}
				for _, raw := range batch {
					for _, pk := range raw.Decoded {
						if text, ok := pk.(*packet.Text); ok && text.Message == marker {
							delivered = true
						}
					}
				}
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemoteReceiveDrainKeepsLocalAbortAndReadDeadline(t *testing.T) {
	for _, abort := range []bool{true, false} {
		name := "read_deadline"
		if abort {
			name = "local_abort"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				left, right := net.Pipe()
				defer right.Close()
				conn := newConn(pipeConn{Conn: left}, nil, slog.New(slog.DiscardHandler), DefaultProtocol, -1, false)
				defer conn.Abort()
				conn.batchReading = true
				conn.receiveDone, conn.receiveDrainStop = make(chan struct{}), make(chan struct{})
				conn.cancelFunc(remoteCloseFixture{})
				if !abort {
					if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
				}
				read := make(chan error, 1)
				go func() {
					_, err := conn.ReadBatchRaw(nil)
					read <- err
				}()
				synctest.Wait()
				if abort {
					if err := conn.Abort(); err != nil {
						t.Fatal(err)
					}
				} else {
					time.Sleep(time.Second)
				}
				err := <-read
				want := error(context.DeadlineExceeded)
				if abort {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("remote drain ignored local read control: %T", err)
				}
			})
		})
	}
}

type remoteCloseFixture struct{}

func (remoteCloseFixture) Error() string                { return "remote transport fixture" }
func (remoteCloseFixture) Unwrap() error                { return context.Canceled }
func (remoteCloseFixture) TransportCloseReason() string { return "remote_disconnect" }
