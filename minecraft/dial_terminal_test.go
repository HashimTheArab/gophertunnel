package minecraft

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestDialRetainsPostLoginFramingAndHeaderFailureCause(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		for _, failure := range []struct {
			name  string
			frame []byte
			cause error
			stage string
		}{
			{name: "batch_length", frame: []byte{0xfe, 0xff, 0x80}, cause: io.ErrUnexpectedEOF, stage: "decoder"},
			{name: "packet_header", frame: []byte{0xfe, 0xff, 1, 0x80}, cause: io.EOF, stage: "packet"},
		} {
			name := "ordinary/" + failure.name
			if prepared {
				name = "prepared/" + failure.name
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					started, damage := make(chan struct{}), make(chan struct{})
					network := newScriptedDialNetwork(func(conn net.Conn) error {
						decoder, encoder, err := preparedScriptSettings(conn)
						if err != nil {
							return err
						}
						if _, err := preparedScriptRead(decoder, packet.IDLogin); err != nil {
							return err
						}
						if err := preparedScriptFinish(decoder, encoder); err != nil {
							return err
						}
						<-started
						if err := encodeScriptedPackets(encoder, &packet.Unknown{PacketID: 700, Payload: []byte{1, 2, 3}}); err != nil {
							return err
						}
						<-damage
						if _, err := conn.Write(failure.frame); err != nil {
							return err
						}
						return expectScriptedClose(conn, decoder)
					})
					dialer := Dialer{FlushRate: -1, RelayStartup: true, EnableBatchReading: true}
					var conn *Conn
					var err error
					if prepared {
						prefix, err := dialer.PrepareContextNetwork(t.Context(), network, "fixture:1", 1)
						if err != nil {
							t.Fatal(err)
						}
						defer prefix.Close()
						<-prefix.Done()
						conn, err = prefix.CommitContext(t.Context(), dialer, "fixture:1", 1)
					} else {
						conn, err = dialer.DialContextNetwork(t.Context(), network, "fixture:1")
					}
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					close(started)
					for found := false; !found; {
						batch, err := conn.ReadBatchRaw(nil)
						if err != nil {
							t.Fatal(err)
						}
						for _, pk := range batch {
							found = found || pk.ID == 700
						}
					}
					if conn.Context().Err() != nil {
						t.Fatal("well-formed unknown data closed the connection")
					}
					close(damage)
					<-conn.Context().Done()
					_, readErr := conn.ReadBatchRaw(nil)
					var opErr *net.OpError
					var receive interface{ ReceiveStage() string }
					if !errors.Is(readErr, failure.cause) || !errors.As(readErr, &opErr) || !errors.As(readErr, &receive) || receive.ReceiveStage() != failure.stage {
						t.Fatalf("fatal framing/header cause was replaced: %v", readErr)
					}
					if !errors.Is(context.Cause(conn.Context()), failure.cause) {
						t.Fatal("connection lifetime discarded the decoder's original terminal cause")
					}
					if err := <-network.done; err != nil {
						t.Fatal(err)
					}
				})
			})
		}
	}
}

func TestDialReceiveCauseSurvivesFinalFlushTransportCancellation(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		name := "ordinary"
		if prepared {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				damage := make(chan struct{})
				base := newScriptedDialNetwork(func(raw net.Conn) error {
					decoder, encoder, err := preparedScriptSettings(raw)
					if err != nil {
						return err
					}
					if _, err = preparedScriptRead(decoder, packet.IDLogin); err != nil {
						return err
					}
					if err = preparedScriptFinish(decoder, encoder); err != nil {
						return err
					}
					<-damage
					if _, err = raw.Write([]byte{0xfe, 0xff, 0x80}); err != nil {
						return err
					}
					frames, err := decoder.Decode()
					if err != nil {
						return err
					}
					if len(frames) != 1 || rawPacketID(frames[0]) != 701 {
						return errors.New("terminal cleanup did not flush the pending outbound packet")
					}
					return expectScriptedClose(raw, decoder)
				})
				transportCtx, cancelTransport := context.WithCancelCause(t.Context())
				defer cancelTransport(net.ErrClosed)
				network := &terminalFlushNetwork{scriptedDialNetwork: base, ctx: transportCtx, cancel: cancelTransport}
				dialer := Dialer{FlushRate: -1, RelayStartup: true, EnableBatchReading: true}
				var conn *Conn
				var err error
				if prepared {
					prefix, prefixErr := dialer.PrepareContextNetwork(t.Context(), network, "fixture:1", 1)
					if prefixErr != nil {
						t.Fatal(prefixErr)
					}
					defer prefix.Close()
					<-prefix.Done()
					conn, err = prefix.CommitContext(t.Context(), dialer, "fixture:1", 1)
				} else {
					conn, err = dialer.DialContextNetwork(t.Context(), network, "fixture:1")
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Abort()
				if err = conn.WritePacket(&packet.Unknown{PacketID: 701, Payload: []byte{7}}); err != nil {
					t.Fatal(err)
				}
				network.armed.Store(true)
				close(damage)
				if err = <-base.done; err != nil {
					t.Fatal(err)
				}
				for {
					_, err = conn.ReadBatchRaw(nil)
					if err != nil {
						break
					}
				}
				if !errors.Is(context.Cause(transportCtx), net.ErrClosed) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("final transport cancellation replaced the earlier receive cause: %v", err)
				}
			})
		})
	}
}

type terminalFlushNetwork struct {
	*scriptedDialNetwork
	ctx    context.Context
	cancel context.CancelCauseFunc
	armed  atomic.Bool
}

func (network *terminalFlushNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	raw, err := network.scriptedDialNetwork.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	return &terminalFlushConn{Conn: raw, network: network}, nil
}

type terminalFlushConn struct {
	net.Conn
	network *terminalFlushNetwork
}

func (conn *terminalFlushConn) Context() context.Context { return conn.network.ctx }

func (conn *terminalFlushConn) Write(data []byte) (int, error) {
	if conn.network.armed.Load() {
		conn.network.cancel(net.ErrClosed)
	}
	return conn.Conn.Write(data)
}

func TestDialEncryptedHeaderFailureKeepsTerminalCauseAndQueuedBatch(t *testing.T) {
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
			damage := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				netConn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				server := netConn.(*Conn)
				defer server.Abort()
				if err = server.SendStartGame(GameData{}); err == nil {
					err = server.Flush()
				}
				if err != nil {
					serverDone <- err
					return
				}
				<-damage
				server.encMu.Lock()
				err = server.enc.Encode([][]byte{{0xc0, 0x05}, {0x80}})
				server.encMu.Unlock()
				serverDone <- err
			}()
			dialer := Dialer{FlushRate: -1, RelayStartup: true, EnableBatchReading: true}
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
				t.Fatal("fixture did not negotiate the real encrypted Login handshake")
			}
			close(damage)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			var delivered bool
			for {
				batch, readErr := conn.ReadBatchRaw(nil)
				if readErr != nil {
					var receive interface{ ReceiveStage() string }
					if !delivered || !errors.Is(readErr, io.EOF) || !errors.As(readErr, &receive) || receive.ReceiveStage() != "packet" {
						t.Fatalf("encrypted terminal lost the queued batch or header cause: delivered=%v error=%v", delivered, readErr)
					}
					break
				}
				for _, raw := range batch {
					delivered = delivered || raw.ID == 704
				}
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiveTerminalMessageIsSafeAndKeepsTypedCause(t *testing.T) {
	original := errors.New("fixture-private-packet-body")
	wrapped := packetReceiveCause(original, binary.AppendUvarint(nil, uint64(packet.IDTransfer)))
	var receive interface{ ReceiveStage() string }
	var id interface{ PacketID() uint32 }
	if !errors.Is(wrapped, original) || !errors.As(wrapped, &receive) || receive.ReceiveStage() != "packet" || !errors.As(wrapped, &id) || id.PacketID() != packet.IDTransfer {
		t.Fatal("safe receive metadata discarded packet identity or original typed cause")
	}
	if strings.Contains(wrapped.Error(), original.Error()) || strings.Contains(wrapped.Error(), "0x") {
		t.Fatal("terminal message exposed packet contents")
	}
}
