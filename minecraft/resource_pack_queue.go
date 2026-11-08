package minecraft

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// resourcePackQueue is used to aid in the handling of resource pack queueing and downloading. Only one
// resource pack is downloaded at a time.
type resourcePackQueue struct {
	packs           []*resource.Pack
	packsToDownload map[string]*resource.Pack
	currentPack     *resource.Pack
	currentOffset   uint64

	packAmount       int
	downloadingPacks map[string]*downloadingPack
	awaitingPacks    map[string]*downloadingPack
	chunkSize        uint32
}

// downloadingPack is a resource pack that is being downloaded by a client connection.
type downloadingPack struct {
	buf        *bytes.Buffer
	chunkCount uint32
	size       uint64
	newFrag    chan resourcePackChunk
	contentKey string
	cacheKey   ResourcePackCacheKey
	event      ResourcePackEvent // chunk-source template for progress events

	window *ResourcePackChunkWindow
}

// resourcePackChunk is a single received chunk of a resource pack, tagged with its index.
type resourcePackChunk struct {
	index uint32
	data  []byte
}

// resourcePackDownloadID returns the "uuid_version" pack ID that ResourcePackClientResponse,
// ResourcePackDataInfo, ResourcePackChunkRequest and ResourcePackChunkData name a transfer by. The vanilla
// client keys its downloads by this full ID, so one UUID offered at two versions is two transfers.
func resourcePackDownloadID(id, version string) string {
	return id + "_" + version
}

// matchesDownloadID reports whether a pack ID received in a pack packet names the pack with the UUID and
// version passed. An ID without a version, or with an empty one, matches on its UUID alone.
func matchesDownloadID(name, id, version string) bool {
	nameUUID, nameVersion, _ := strings.Cut(name, "_")
	return resource.CanonicalUUID(nameUUID) == id && (nameVersion == "" || resource.SameVersion(nameVersion, version))
}

// lookupTransfer returns the key and transfer in transfers that a pack ID received from the server names.
// A versioned ID is compared by parsed UUID and version, so "1.0" reaches the "1.0.0" transfer, and never
// reaches another version's transfer. An ID naming a UUID alone reaches the only transfer with that UUID.
func lookupTransfer(transfers map[string]*downloadingPack, name string) (string, *downloadingPack, bool) {
	nameUUID, nameVersion, _ := strings.Cut(name, "_")
	nameUUID = resource.CanonicalUUID(nameUUID)
	if nameVersion != "" {
		key := resourcePackDownloadID(nameUUID, resource.CanonicalVersion(nameVersion))
		pack, ok := transfers[key]
		return key, pack, ok
	}
	var (
		key   string
		match *downloadingPack
	)
	for candidate, pack := range transfers {
		if candidateUUID, _, _ := strings.Cut(candidate, "_"); candidateUUID != nameUUID {
			continue
		}
		if match != nil {
			// Several versions of this UUID are pending, so a bare UUID is ambiguous.
			return "", nil, false
		}
		key, match = candidate, pack
	}
	return key, match, match != nil
}

// Request 'requests' all resource packs passed, provided they all exist in the resourcePackQueue. Clients
// generally request packs as "uuid_version", and ResourcePackDataInfo must use that same identifier shape so
// the client can match the response to its request. Bare UUID requests are accepted for compatibility.
func (queue *resourcePackQueue) Request(packs []string) error {
	queue.packsToDownload = make(map[string]*resource.Pack)
	for _, requestedPackID := range packs {
		found := false
		for _, pack := range queue.packs {
			if matchesDownloadID(requestedPackID, pack.UUID().String(), pack.Version()) {
				queue.packsToDownload[resourcePackDownloadID(pack.UUID().String(), pack.Version())] = pack
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("resource pack (UUID=%v) not found", requestedPackID)
		}
	}
	return nil
}

// NextPack assigns the next resource pack to the current pack and returns true if successful. If there were
// no more packs to assign, false is returned. If ok is true, a packet with data info is returned.
func (queue *resourcePackQueue) NextPack() (pk *packet.ResourcePackDataInfo, ok bool, err error) {
	for index, pack := range queue.packsToDownload {
		delete(queue.packsToDownload, index)
		chunkCount, ok := resource.ChunkCount(uint64(pack.Size()), queue.chunkSize)
		if !ok {
			return nil, false, fmt.Errorf("resource pack %v has too many chunks", pack.UUID())
		}

		queue.currentPack = pack
		queue.currentOffset = 0
		checksum := pack.Checksum()

		var packType byte
		switch {
		case pack.HasWorldTemplate():
			packType = packet.ResourcePackTypeWorldTemplate
		case pack.HasTextures() && (pack.HasBehaviours() || pack.HasScripts()):
			packType = packet.ResourcePackTypeAddon
		case !pack.HasTextures() && (pack.HasBehaviours() || pack.HasScripts()):
			packType = packet.ResourcePackTypeBehaviour
		case pack.HasTextures():
			packType = packet.ResourcePackTypeResources
		default:
			packType = packet.ResourcePackTypeSkins
		}
		return &packet.ResourcePackDataInfo{
			UUID:          resourcePackDownloadID(pack.UUID().String(), pack.Version()),
			DataChunkSize: queue.chunkSize,
			ChunkCount:    chunkCount,
			Size:          uint64(pack.Size()),
			Hash:          checksum[:],
			PackType:      packType,
		}, true, nil
	}
	return nil, false, nil
}

// AllDownloaded checks if all resource packs in the queue are downloaded.
func (queue *resourcePackQueue) AllDownloaded() bool {
	return len(queue.packsToDownload) == 0
}
