package minecraft

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestReadBatchRequiresBatchReading(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()

	if _, err := conn.ReadBatch(); !errors.Is(err, errBatchReadingDisabled) {
		t.Fatalf("ReadBatch error = %v, want %v", err, errBatchReadingDisabled)
	}
}

func TestBatchReadingRejectsSinglePacketReads(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.batchReading = true

	tests := []struct {
		name string
		read func() error
	}{
		{name: "ReadPacket", read: func() error {
			_, err := conn.ReadPacket()
			return err
		}},
		{name: "ReadBytes", read: func() error {
			_, err := conn.ReadBytes()
			return err
		}},
		{name: "Read", read: func() error {
			_, err := conn.Read(make([]byte, 1))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn.readDeadline = time.After(time.Millisecond)
			if err := test.read(); !errors.Is(err, errSinglePacketReadInBatchMode) {
				t.Fatalf("%s error = %v, want %v", test.name, err, errSinglePacketReadInBatchMode)
			}
		})
	}
}

func TestReadBatchReturnsAllDeferredPackets(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.batchReading = true
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 700}, payload: bytes.NewBuffer(nil)})
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 701}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()

	packets, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(packets) != 2 || packets[0].ID() != 700 || packets[1].ID() != 701 {
		t.Fatalf("ReadBatch IDs = %v, want [700 701]", packetIDs(packets))
	}
}

func TestReadBatchPreservesDeferredBatchBoundaries(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.batchReading = true
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 700}, payload: bytes.NewBuffer(nil)})
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 701}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 702}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()

	first, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch first batch: %v", err)
	}
	if ids := packetIDs(first); len(ids) != 2 || ids[0] != 700 || ids[1] != 701 {
		t.Fatalf("first batch IDs = %v, want [700 701]", ids)
	}
	second, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch second batch: %v", err)
	}
	if ids := packetIDs(second); len(ids) != 1 || ids[0] != 702 {
		t.Fatalf("second batch IDs = %v, want [702]", ids)
	}
}

func TestReadBatchMergesDeferredAndCollectedFromSameBatch(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.batchReading = true

	// One wire batch where a packet was deferred during login and a later packet was collected after
	// login completed must map to a single ReadBatch result, in wire order.
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 700}, payload: bytes.NewBuffer(nil)})
	conn.collectPacket(&packetData{h: &packet.Header{PacketID: 701}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()

	packets, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if ids := packetIDs(packets); len(ids) != 2 || ids[0] != 700 || ids[1] != 701 {
		t.Fatalf("ReadBatch IDs = %v, want [700 701] in one batch", ids)
	}
	conn.readDeadline = time.After(10 * time.Millisecond)
	if extra, err := conn.ReadBatch(); err == nil {
		t.Fatalf("wire batch was split: second ReadBatch returned %v", packetIDs(extra))
	}
}

func TestReadBatchDropsPacketsCollectedAfterClose(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	// A dialer-side conn: its pool contains Disconnect, so receiving one closes the connection.
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.pool = conn.proto.Packets(false)
	conn.batchReading = true
	conn.loggedIn = true

	disconnectFrame, err := encodePacket(&packet.Disconnect{})
	if err != nil {
		t.Fatalf("encode disconnect: %v", err)
	}
	gameplayFrame, err := encodePacket(&packet.Unknown{PacketID: 778})
	if err != nil {
		t.Fatalf("encode packet: %v", err)
	}

	// A batch [Disconnect, gameplay]: the disconnect closes the connection, so the gameplay packet
	// after it must be dropped, matching single-packet mode.
	if err := conn.receive(disconnectFrame); err != nil {
		t.Fatalf("receive disconnect: %v", err)
	}
	if err := conn.receive(gameplayFrame); err != nil {
		t.Fatalf("receive gameplay: %v", err)
	}
	conn.flushBatch()

	if packets, err := conn.ReadBatch(); err == nil {
		t.Fatalf("ReadBatch delivered post-close packets %v, want a close error", packetIDs(packets))
	}
}

func TestReadBatchOrdersDeferredAfterQueuedBatches(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.batchReading = true

	// A batch is queued for reading first; a packet deferred afterwards must not overtake it.
	conn.collectPacket(&packetData{h: &packet.Header{PacketID: 700}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()
	conn.deferPacket(&packetData{h: &packet.Header{PacketID: 701}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()

	first, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch first batch: %v", err)
	}
	if ids := packetIDs(first); len(ids) != 1 || ids[0] != 700 {
		t.Fatalf("first batch IDs = %v, want [700]", ids)
	}
	second, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch second batch: %v", err)
	}
	if ids := packetIDs(second); len(ids) != 1 || ids[0] != 701 {
		t.Fatalf("second batch IDs = %v, want [701]", ids)
	}
}

func TestReadBatchStopsAfterConnClosingDecodeError(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.pool = conn.proto.Packets(false)
	conn.batchReading = true
	conn.disconnectOnInvalidPacket = true

	// A batch [valid, invalid, valid]: decoding the invalid packet closes the connection, so the valid
	// packet after it must not be delivered.
	conn.collectPacket(&packetData{h: &packet.Header{PacketID: 777}, payload: bytes.NewBuffer(nil)})
	conn.collectPacket(&packetData{h: &packet.Header{PacketID: packet.IDText}, payload: bytes.NewBuffer([]byte{0xff})})
	conn.collectPacket(&packetData{h: &packet.Header{PacketID: 778}, payload: bytes.NewBuffer(nil)})
	conn.flushBatch()

	packets, err := conn.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if ids := packetIDs(packets); len(ids) != 1 || ids[0] != 777 {
		t.Fatalf("ReadBatch IDs = %v, want only [777]", ids)
	}
	if conn.ctx.Err() == nil {
		t.Fatal("invalid packet with disconnectOnInvalidPacket did not close the connection")
	}
}

func TestDecodePacketDoesNotApplyDisconnectPolicy(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	converted := false
	proto := conversionTrackingProtocol{Protocol: DefaultProtocol, called: &converted}
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), proto, -1, false)
	defer conn.Close()
	conn.pool = conn.proto.Packets(false)
	conn.disconnectOnInvalidPacket = true

	payload := new(bytes.Buffer)
	(&packet.Transfer{Address: "example.com", Port: 19132}).Marshal(DefaultProtocol.NewWriter(payload, 0))
	_ = payload.WriteByte(0xff)
	data := &packetData{h: &packet.Header{PacketID: packet.IDTransfer}, payload: payload}
	if _, err := data.decodePacket(conn); err == nil {
		t.Fatal("decodePacket accepted malformed packet")
	}
	if conn.ctx.Err() != nil {
		t.Fatal("decodePacket applied the connection disconnect policy")
	}
	if converted {
		t.Fatal("decodePacket converted a malformed packet")
	}
}

type conversionTrackingProtocol struct {
	Protocol
	called *bool
}

func (p conversionTrackingProtocol) ConvertToLatest(pk packet.Packet, conn *Conn) []packet.Packet {
	*p.called = true
	return p.Protocol.ConvertToLatest(pk, conn)
}

func TestReadBatchDeliversPacketsBeforeDisconnect(t *testing.T) {
	packetFrame, err := encodePacket(&packet.Unknown{PacketID: 777})
	if err != nil {
		t.Fatalf("encode packet: %v", err)
	}
	disconnectFrame, err := encodePacket(&packet.Disconnect{})
	if err != nil {
		t.Fatalf("encode disconnect: %v", err)
	}

	// The batch is flushed and the context cancelled from the same goroutine, so a reader already
	// blocked on ReadBatch sees both ready at once. Repeat with a short pause so the reader reaches
	// the blocking select before the disconnect arrives, exposing the race.
	for range 50 {
		client, serverConn := net.Pipe()

		// A dialer-side conn: its pool contains Disconnect, so receiving one closes the connection.
		conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
		conn.pool = conn.proto.Packets(false)
		conn.batchReading = true
		conn.loggedIn = true

		type result struct {
			packets []packet.Packet
			err     error
		}
		resultCh := make(chan result, 1)
		go func() {
			packets, err := conn.ReadBatch()
			resultCh <- result{packets: packets, err: err}
		}()
		time.Sleep(time.Millisecond)

		if err := conn.receive(packetFrame); err != nil {
			t.Fatalf("receive packet: %v", err)
		}
		if err := conn.receive(disconnectFrame); err != nil {
			t.Fatalf("receive disconnect: %v", err)
		}

		select {
		case got := <-resultCh:
			if got.err != nil {
				t.Fatalf("ReadBatch lost the packets before the disconnect: %v", got.err)
			}
			if len(got.packets) != 1 || got.packets[0].ID() != 777 {
				t.Fatalf("pre-disconnect batch IDs = %v, want [777]", packetIDs(got.packets))
			}
		case <-time.After(time.Second):
			t.Fatal("ReadBatch did not return the batch preceding the disconnect")
		}
		if _, err := conn.ReadBatch(); err == nil {
			t.Fatal("ReadBatch after disconnect returned no error")
		}
		_ = conn.Close()
		_ = serverConn.Close()
	}
}

func packetIDs(packets []packet.Packet) []uint32 {
	ids := make([]uint32, len(packets))
	for i, pk := range packets {
		ids[i] = pk.ID()
	}
	return ids
}

func TestStartGameWritesPropertyData(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()

	var got map[string]any
	conn.packetFunc = func(header packet.Header, payload []byte, _, _ net.Addr) {
		if header.PacketID != packet.IDStartGame {
			return
		}
		var start packet.StartGame
		start.Marshal(protocol.NewReader(bytes.NewBuffer(payload), 0, false))
		got = start.PropertyData
	}

	if err := conn.SendStartGame(GameData{
		PropertyData: map[string]any{
			"gophertunnel:test": int32(1),
		},
	}); err != nil {
		t.Fatalf("SendStartGame: %v", err)
	}

	if got["gophertunnel:test"] != int32(1) {
		t.Fatalf("StartGame.PropertyData = %#v, want gophertunnel:test=1", got)
	}
}

func TestGameDataRoundTripsDayCycleLockTime(t *testing.T) {
	t.Parallel()

	const want int32 = 12_345
	data := GameDataFromStartGame(&packet.StartGame{DayCycleLockTime: want})
	if data.DayCycleLockTime != want {
		t.Fatalf("GameData.DayCycleLockTime = %d, want %d", data.DayCycleLockTime, want)
	}

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()

	var got int32
	conn.packetFunc = func(header packet.Header, payload []byte, _, _ net.Addr) {
		if header.PacketID != packet.IDStartGame {
			return
		}
		var start packet.StartGame
		start.Marshal(protocol.NewReader(bytes.NewBuffer(payload), 0, false))
		got = start.DayCycleLockTime
	}

	if err := conn.SendStartGame(data); err != nil {
		t.Fatalf("SendStartGame: %v", err)
	}
	if got != want {
		t.Fatalf("StartGame.DayCycleLockTime = %d, want %d", got, want)
	}
}

func TestResourcePacksInfoUsesConfiguredWorldTemplateFields(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()

	templateUUID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	conn.forceDisableVibrantVisuals = true
	conn.resourcePackWorldTemplateUUID = templateUUID
	conn.resourcePackWorldTemplateVersion = "*"

	var got packet.ResourcePacksInfo
	conn.packetFunc = func(header packet.Header, payload []byte, _, _ net.Addr) {
		if header.PacketID != packet.IDResourcePacksInfo {
			return
		}
		got.Marshal(protocol.NewReader(bytes.NewBuffer(payload), 0, false))
	}

	if err := conn.handleClientToServerHandshake(); err != nil {
		t.Fatalf("handleClientToServerHandshake: %v", err)
	}

	if got.WorldTemplateUUID != templateUUID || got.WorldTemplateVersion != "*" {
		t.Fatalf("ResourcePacksInfo template = %s %q, want %s *", got.WorldTemplateUUID, got.WorldTemplateVersion, templateUUID)
	}
	if !got.ForceDisableVibrantVisuals {
		t.Fatal("ResourcePacksInfo ForceDisableVibrantVisuals = false, want true")
	}
}

func TestHandleLoginSkipsServerHandshakeWhenEncryptionDisabled(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.disableEncryption = true
	conn.authEnabled = false

	var identityData login.IdentityData
	defaultIdentityData(&identityData)
	var clientData login.ClientData
	defaultClientData("127.0.0.1:19132", identityData.DisplayName, &clientData)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var sawServerHandshake, sawResourcePacksInfo bool
	conn.packetFunc = func(header packet.Header, _ []byte, _, _ net.Addr) {
		switch header.PacketID {
		case packet.IDServerToClientHandshake:
			sawServerHandshake = true
		case packet.IDResourcePacksInfo:
			sawResourcePacksInfo = true
		}
	}

	err = conn.handleLogin(&packet.Login{ConnectionRequest: login.EncodeOffline(identityData, clientData, key)})
	if err != nil {
		t.Fatalf("handleLogin: %v", err)
	}
	if sawServerHandshake {
		t.Fatal("ServerToClientHandshake was sent despite disabled encryption")
	}
	if !sawResourcePacksInfo {
		t.Fatal("ResourcePacksInfo was not sent")
	}
	if !conn.handshakeComplete {
		t.Fatal("handshakeComplete = false, want true")
	}
}

func TestClientCacheStatusSendsEmptyResourcePackStack(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()
	conn.handshakeComplete = true

	var got packet.ResourcePackStack
	var sawResourcePackStack bool
	conn.packetFunc = func(header packet.Header, payload []byte, _, _ net.Addr) {
		if header.PacketID == packet.IDResourcePackStack {
			sawResourcePackStack = true
			got.Marshal(protocol.NewReader(bytes.NewBuffer(payload), 0, false))
		}
	}

	if err := conn.handleClientCacheStatus(&packet.ClientCacheStatus{Enabled: true}); err != nil {
		t.Fatalf("handleClientCacheStatus: %v", err)
	}
	if !sawResourcePackStack {
		t.Fatal("ResourcePackStack was not sent")
	}
	if got.BaseGameVersion != "*" {
		t.Fatalf("ResourcePackStack.BaseGameVersion = %q, want *", got.BaseGameVersion)
	}
	if len(got.Experiments) != 0 || got.ExperimentsPreviouslyToggled {
		t.Fatalf("ResourcePackStack experiments = %#v previouslyToggled=%v, want none/false", got.Experiments, got.ExperimentsPreviouslyToggled)
	}
}

func TestDisconnectWritesDisconnectPacket(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()

	conn := newConn(serverConn, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.Disconnect("closing")
	}()

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	packets, err := packet.NewDecoder(client).Decode()
	if err != nil {
		t.Fatalf("decode disconnect packet: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("decoded packet count = %d, want 1", len(packets))
	}
	buf := bytes.NewBuffer(packets[0])
	var header packet.Header
	if err := header.Read(buf); err != nil {
		t.Fatalf("read packet header: %v", err)
	}
	if header.PacketID != packet.IDDisconnect {
		t.Fatalf("packet ID = %d, want Disconnect", header.PacketID)
	}
	var disconnect packet.Disconnect
	disconnect.Marshal(protocol.NewReader(buf, 0, false))
	if disconnect.Message != "closing" {
		t.Fatalf("disconnect message = %q, want closing", disconnect.Message)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
}

func TestDisconnectPacketWritesDisconnectReason(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()

	conn := newConn(serverConn, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.DisconnectPacket(packet.Disconnect{
			Reason:          packet.DisconnectReasonServerFull,
			FilteredMessage: "Server Full",
		})
	}()

	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	packets, err := packet.NewDecoder(client).Decode()
	if err != nil {
		t.Fatalf("decode disconnect packet: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("decoded packet count = %d, want 1", len(packets))
	}
	buf := bytes.NewBuffer(packets[0])
	var header packet.Header
	if err := header.Read(buf); err != nil {
		t.Fatalf("read packet header: %v", err)
	}
	if header.PacketID != packet.IDDisconnect {
		t.Fatalf("packet ID = %d, want Disconnect", header.PacketID)
	}
	var disconnect packet.Disconnect
	disconnect.Marshal(protocol.NewReader(buf, 0, false))
	if disconnect.Reason != packet.DisconnectReasonServerFull {
		t.Fatalf("disconnect reason = %d, want %d", disconnect.Reason, packet.DisconnectReasonServerFull)
	}
	if disconnect.FilteredMessage != "Server Full" {
		t.Fatalf("filtered message = %q, want Server Full", disconnect.FilteredMessage)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("DisconnectPacket: %v", err)
	}
}

func TestReceiveDisconnectPreservesPacketReason(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	conn.pool = conn.proto.Packets(false)
	defer conn.Close()

	var buf bytes.Buffer
	header := packet.Header{PacketID: packet.IDDisconnect}
	if err := header.Write(&buf); err != nil {
		t.Fatalf("write header: %v", err)
	}
	(&packet.Disconnect{
		Reason:          packet.DisconnectReasonServerFull,
		Message:         "",
		FilteredMessage: "Server Full",
	}).Marshal(protocol.NewWriter(&buf, 0))

	if err := conn.receive(buf.Bytes()); err != nil {
		t.Fatalf("receive disconnect: %v", err)
	}

	cause := context.Cause(conn.Context())
	var packetErr *DisconnectPacketError
	if !errors.As(cause, &packetErr) {
		t.Fatalf("cause %v does not contain DisconnectPacketError", cause)
	}
	if packetErr.Reason != packet.DisconnectReasonServerFull {
		t.Fatalf("reason = %d, want %d", packetErr.Reason, packet.DisconnectReasonServerFull)
	}
	if packetErr.FilteredMessage != "Server Full" {
		t.Fatalf("filtered message = %q, want Server Full", packetErr.FilteredMessage)
	}
	if packetErr.Error() != "Server Full" {
		t.Fatalf("error = %q, want Server Full", packetErr.Error())
	}

	var legacyErr DisconnectError
	if !errors.As(cause, &legacyErr) {
		t.Fatalf("cause %v does not contain legacy DisconnectError", cause)
	}
	if legacyErr.Error() != "Server Full" {
		t.Fatalf("legacy error = %q, want Server Full", legacyErr.Error())
	}
}

func TestAbortCancelsContextAndClosesTransport(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)

	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Abort did not cancel connection context")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := peer.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("peer read error = %v, want terminal close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer read remained blocked after Abort")
	}
	if err := conn.Abort(); err != nil {
		t.Fatalf("second Abort: %v", err)
	}
}

func TestAbortUnblocksCloseStuckFlushing(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	observed := &writeObservedConn{Conn: client, started: make(chan struct{})}
	conn := newConn(observed, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("queue write: %v", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case <-observed.started:
	case <-time.After(time.Second):
		t.Fatal("Close did not begin its flush")
	}
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Abort did not unblock Close")
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("connection context remained active")
	}
}

func TestClosePanicStillCancelsAndClosesTransport(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	panicking := &panicWriteConn{Conn: client, closed: make(chan struct{})}
	conn := newConn(panicking, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("queue write: %v", err)
	}

	err := conn.Close()
	if err == nil || !strings.Contains(err.Error(), "panic flushing connection") {
		t.Fatalf("Close error = %v, want recovered flush panic", err)
	}
	select {
	case <-panicking.closed:
	case <-time.After(time.Second):
		t.Fatal("Close panic left raw transport open")
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Close panic left context active")
	}
}

type writeObservedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *writeObservedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type panicWriteConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *panicWriteConn) Write([]byte) (int, error) {
	panic("write panic")
}

func (c *panicWriteConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestClientToServerHandshakeMarksComplete(t *testing.T) {
	t.Parallel()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
	defer conn.Close()

	if conn.handshakeComplete {
		t.Fatal("handshakeComplete was true before ClientToServerHandshake")
	}
	if err := conn.handleClientToServerHandshake(); err != nil {
		t.Fatalf("handleClientToServerHandshake: %v", err)
	}
	if !conn.handshakeComplete {
		t.Fatal("handshakeComplete was false after ClientToServerHandshake")
	}
}

func TestHandleResourcePacksInfoCountsURLDownloadedPacks(t *testing.T) {
	t.Parallel()

	urlPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	chunkPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440002")
	urlPack := testResourcePackArchive(t, urlPackID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(urlPack)
	}))
	defer server.Close()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
	defer conn.Close()

	err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{
			UUID:        urlPackID,
			Version:     "1.0.0",
			Size:        uint64(len(urlPack)),
			DownloadURL: server.URL,
		},
		{
			UUID:    chunkPackID,
			Version: "1.0.0",
			Size:    1,
		},
	}})
	if err != nil {
		t.Fatalf("handleResourcePacksInfo: %v", err)
	}
	if conn.packQueue.packAmount != 1 {
		t.Fatalf("packAmount = %d, want 1", conn.packQueue.packAmount)
	}
	if _, ok := conn.packQueue.downloadingPacks[chunkPackID.String()]; !ok {
		t.Fatalf("chunk pack was not queued for chunk download")
	}
	if len(conn.resourcePacks) != 1 {
		t.Fatalf("resourcePacks length = %d, want 1", len(conn.resourcePacks))
	}
}

func TestHandleResourcePacksInfoFallsBackWhenURLExceedsAdvertisedSize(t *testing.T) {
	t.Parallel()

	urlPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	urlPack := testResourcePackArchive(t, urlPackID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(append(urlPack, 0))
	}))
	defer server.Close()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
	defer conn.Close()

	err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{
			UUID:        urlPackID,
			Version:     "1.0.0",
			Size:        uint64(len(urlPack)),
			DownloadURL: server.URL,
		},
	}})
	if err != nil {
		t.Fatalf("handleResourcePacksInfo: %v", err)
	}
	if conn.packQueue.packAmount != 1 {
		t.Fatalf("packAmount = %d, want 1", conn.packQueue.packAmount)
	}
	if _, ok := conn.packQueue.downloadingPacks[urlPackID.String()]; !ok {
		t.Fatalf("oversized URL pack was not queued for chunk download fallback")
	}
	if len(conn.resourcePacks) != 0 {
		t.Fatalf("resourcePacks length = %d, want 0", len(conn.resourcePacks))
	}
}

func TestHandleResourcePacksInfoFallsBackWhenURLPackIdentityMismatch(t *testing.T) {
	t.Parallel()

	advertisedPackID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	urlPack := testResourcePackArchive(t, uuid.MustParse("550e8400-e29b-41d4-a716-446655440002"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(urlPack)
	}))
	defer server.Close()

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()

	conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, time.Second/20, false)
	defer conn.Close()

	err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{TexturePacks: []protocol.TexturePackInfo{
		{
			UUID:        advertisedPackID,
			Version:     "1.0.0",
			Size:        uint64(len(urlPack)),
			DownloadURL: server.URL,
		},
	}})
	if err != nil {
		t.Fatalf("handleResourcePacksInfo: %v", err)
	}
	if conn.packQueue.packAmount != 1 {
		t.Fatalf("packAmount = %d, want 1", conn.packQueue.packAmount)
	}
	if _, ok := conn.packQueue.downloadingPacks[advertisedPackID.String()]; !ok {
		t.Fatalf("mismatched URL pack was not queued for chunk download fallback")
	}
	if len(conn.resourcePacks) != 0 {
		t.Fatalf("resourcePacks length = %d, want 0", len(conn.resourcePacks))
	}
}

func testResourcePackArchive(t *testing.T, id uuid.UUID) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	w, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("create manifest: %v", err)
	}
	_, _ = w.Write([]byte(`{
		"format_version": 2,
		"header": {
			"name": "test pack",
			"description": "test pack",
			"uuid": "` + id.String() + `",
			"version": [1, 0, 0],
			"min_engine_version": [1, 20, 0]
		},
		"modules": [{
			"description": "test pack",
			"type": "resources",
			"uuid": "550e8400-e29b-41d4-a716-446655440001",
			"version": [1, 0, 0]
		}]
	}`))
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
