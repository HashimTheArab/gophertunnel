package minecraft

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// compressionTestConn stores each direction separately for synchronous in-memory negotiation tests.
type compressionTestConn struct {
	recordingConn
	incoming bytes.Buffer
	outgoing bytes.Buffer
}

// Read consumes the next batch supplied by the peer encoder.
func (c *compressionTestConn) Read(b []byte) (int, error) { return c.incoming.Read(b) }

// Write stores the connection's outgoing batch for comparison with the peer envelope.
func (c *compressionTestConn) Write(b []byte) (int, error) { return c.outgoing.Write(b) }

func TestNetworkSettingsNone(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			for _, previous := range []bool{false, true} {
				name := "initial"
				if previous {
					name = "previously enabled"
				}
				t.Run(name, func(t *testing.T) {
					raw := new(compressionTestConn)
					conn := newConn(raw, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
					defer conn.Close()
					conn.maxDecompressedLen = 4096
					peer := packet.NewEncoder(&raw.incoming)
					var expected bytes.Buffer
					reference := packet.NewEncoder(&expected)
					if encrypted {
						key := [32]byte{1, 2, 3}
						conn.enc.EnableEncryption(key)
						conn.dec.EnableEncryption(key)
						peer.EnableEncryption(key)
						reference.EnableEncryption(key)
					}
					var stats packet.BatchEncodeStats
					conn.enc.SetBatchEncodeObserver(func(s packet.BatchEncodeStats) { stats = s })
					payload := bytes.Repeat([]byte{7}, 2048)
					exchange := func() {
						t.Helper()
						if err := reference.Encode([][]byte{payload}); err != nil {
							t.Fatal(err)
						}
						if err := conn.enc.Encode([][]byte{payload}); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(raw.outgoing.Bytes(), expected.Bytes()) {
							t.Fatalf("outgoing wire differs from peer framing: got %d bytes, want %d", raw.outgoing.Len(), expected.Len())
						}
						raw.outgoing.Reset()
						expected.Reset()
						if err := peer.Encode([][]byte{payload}); err != nil {
							t.Fatal(err)
						}
						packets, err := conn.dec.Decode()
						if err != nil {
							t.Fatal(err)
						}
						if len(packets) != 1 || !bytes.Equal(packets[0], payload) {
							t.Fatalf("incoming packet changed: %x", packets)
						}
					}
					if previous {
						if err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: packet.CompressionAlgorithmFlate, CompressionThreshold: 1}); err != nil {
							t.Fatal(err)
						}
						peer.EnableCompression(packet.FlateCompression, 1)
						reference.EnableCompression(packet.FlateCompression, 1)
						exchange()
					}
					if err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: packet.CompressionAlgorithmNone, CompressionThreshold: 1}); err != nil {
						t.Fatal(err)
					}
					// The peer switches envelope mode without recreating its encryption state.
					peer.EnableCompression(nil, 0)
					reference.EnableCompression(nil, 0)
					for range 2 {
						exchange()
						wantLen := stats.UncompressedLen
						if encrypted {
							wantLen += 8
						}
						if stats.Compressed || stats.CompressionID != packet.CompressionAlgorithmNone || stats.OutputLen != wantLen {
							t.Fatalf("None negotiation kept compression framing: %+v", stats)
						}
					}
					// The decompressed-size limit still applies after the envelope is disabled.
					if err := peer.Encode([][]byte{bytes.Repeat([]byte{7}, 4096)}); err != nil {
						t.Fatal(err)
					}
					if _, err := conn.dec.Decode(); err == nil {
						t.Fatal("None negotiation removed the batch size limit")
					}
				})
			}
		})
	}
}

func TestRequestNetworkSettingsNone(t *testing.T) {
	raw := new(compressionTestConn)
	conn := newConn(raw, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, true)
	defer conn.Close()
	conn.acceptedProto = []Protocol{DefaultProtocol}
	conn.compression = packet.FlateCompression
	conn.compressionSelector = func(Protocol) packet.Compression { return packet.NopCompression }
	if err := conn.handleRequestNetworkSettings(&packet.RequestNetworkSettings{ClientProtocol: DefaultProtocol.ID()}); err != nil {
		t.Fatal(err)
	}
	packets, err := packet.NewDecoder(&raw.outgoing).Decode()
	if err != nil || len(packets) != 1 {
		t.Fatalf("NetworkSettings response: %x, %v", packets, err)
	}
	reader := testConn()
	reader.pool = DefaultProtocol.Packets(false)
	settings, err := parseData(packets[0], reader)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := settings.decode(reader)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("decode NetworkSettings: %v, %v", decoded, err)
	}
	if settings, ok := decoded[0].(*packet.NetworkSettings); !ok || settings.CompressionAlgorithm != packet.CompressionAlgorithmNone {
		t.Fatalf("advertised settings = %#v", decoded[0])
	}
	payload := []byte{packet.IDClientToServerHandshake}
	if err := conn.enc.Encode([][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.outgoing.Bytes(), []byte{0xfe, 1, packet.IDClientToServerHandshake}) {
		t.Fatalf("None server output = %x", raw.outgoing.Bytes())
	}
	peer := packet.NewEncoder(&raw.incoming)
	if err := peer.Encode([][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	if packets, err := conn.dec.Decode(); err != nil || len(packets) != 1 || !bytes.Equal(packets[0], payload) {
		t.Fatalf("None server input = %x, %v", packets, err)
	}
}

func TestNetworkSettingsUnknownAlgorithm(t *testing.T) {
	raw := new(compressionTestConn)
	conn := newConn(raw, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	if err := conn.handleNetworkSettings(&packet.NetworkSettings{CompressionAlgorithm: 42, CompressionThreshold: 1}); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{7}, 2048)
	if err := conn.enc.Encode([][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	if raw.outgoing.Bytes()[1] != byte(packet.DefaultCompression.EncodeCompression()) {
		t.Fatalf("unknown algorithm did not use default compression: %x", raw.outgoing.Bytes()[:2])
	}
	peer := packet.NewEncoder(&raw.incoming)
	peer.EnableCompression(packet.DefaultCompression, 1)
	if err := peer.Encode([][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	if packets, err := conn.dec.Decode(); err != nil || len(packets) != 1 || !bytes.Equal(packets[0], payload) {
		t.Fatalf("default-compressed input = %x, %v", packets, err)
	}
}
