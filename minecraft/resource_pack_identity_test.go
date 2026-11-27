package minecraft

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"testing/synctest"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

type identityPackCache struct{ stores int }

func (*identityPackCache) Load(context.Context, ResourcePackCacheKey) (*resource.Pack, error) {
	return nil, nil
}

func (cache *identityPackCache) Store(context.Context, ResourcePackCacheKey, *resource.Pack) error {
	cache.stores++
	return nil
}

// A completed chunk transfer binds its wire identity even when the archive's manifest differs.
func TestChunkPackKeepsAdvertisedIdentityAndOriginalArchive(t *testing.T) {
	for _, multiplier := range []uint64{1, 3} {
		t.Run(fmt.Sprintf("advertised-size-%dx", multiplier), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, peer := net.Pipe()
				defer client.Close()
				defer peer.Close()
				go func() { _, _ = io.Copy(io.Discard, peer) }()
				conn := newConn(client, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
				defer conn.Abort()
				cache := new(identityPackCache)
				conn.resourcePackCache = cache
				wireID, manifestID := uuid.New(), uuid.New()
				const wireVersion = "9.8.7"
				archive := testResourcePackArchive(t, manifestID)
				advertisedSize := uint64(len(archive)) * multiplier
				if err := conn.handleResourcePacksInfo(&packet.ResourcePacksInfo{
					TexturePackRequired: true,
					TexturePacks:        []protocol.TexturePackInfo{{UUID: wireID, Version: wireVersion, Size: advertisedSize}},
				}); err != nil {
					t.Fatal(err)
				}
				if err := conn.handleResourcePackDataInfo(&packet.ResourcePackDataInfo{
					UUID: wireID.String() + "_" + wireVersion, DataChunkSize: uint32(len(archive)), Size: uint64(len(archive)),
				}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if err := conn.handleResourcePackChunkData(&packet.ResourcePackChunkData{
					UUID: wireID.String() + "_" + wireVersion, Data: archive,
				}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				offer, ok := conn.ResourcePackOffer()
				if !ok || len(offer.TexturePacks()) != 1 {
					t.Fatal("missing resource pack offer")
				}
				entry := offer.TexturePacks()[0]
				pack := entry.Pack()
				if pack == nil {
					t.Fatal("completed download was detached from its advertised identity")
				}
				if entry.Info().Size != advertisedSize || pack.UUID() != wireID || pack.Version() != wireVersion {
					t.Fatal("wire identity or original advertisement changed")
				}
				if pack.Manifest().Header.UUID != manifestID || pack.Size() != len(archive) {
					t.Fatal("archive metadata changed")
				}
				got, err := io.ReadAll(io.NewSectionReader(pack, 0, int64(pack.Size())))
				if err != nil || !bytes.Equal(got, archive) {
					t.Fatal("downloaded archive bytes changed")
				}
				clone := pack.Clone()
				rebound := clone.WithTransferIdentity(uuid.New(), "4.5.6")
				if pack.UUID() != wireID || clone.UUID() != wireID || rebound.UUID() == wireID ||
					rebound.Manifest().Header.UUID != manifestID || rebound.Checksum() != pack.Checksum() {
					t.Fatal("rebinding changed another view or its archive metadata")
				}
				if cache.stores != 0 {
					t.Fatal("mismatched manifest was stored under an unverified cache identity")
				}
				if err := conn.handleResourcePackStack(&packet.ResourcePackStack{
					TexturePackRequired: true,
					TexturePacks:        []protocol.StackResourcePack{{UUID: wireID.String(), Version: wireVersion}},
				}); err != nil {
					t.Fatal(err)
				}
				stack, _ := conn.ResourcePackStack()
				if len(stack.Packs()) != 1 || stack.Entries()[0].Pack() == nil {
					t.Fatal("required stack lost the acquired pack")
				}
				projected, _ := ProjectResourcePacks(offer, stack, func(*resource.Pack) bool { return true })
				if projected.TexturePacks()[0].Info().Size != uint64(len(archive)) {
					t.Fatal("forwarded offer did not use the actual transfer size")
				}
			})
		})
	}
}
