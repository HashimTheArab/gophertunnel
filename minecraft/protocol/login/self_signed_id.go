package login

import (
	"crypto/md5"
	"encoding/binary"

	"github.com/google/uuid"
)

// DeriveSelfSignedID returns the version-3 login UUID derived from the full signed
// client ID's little-endian bit pattern followed by the exact device string bytes.
// Each eight-byte digest word is formatted from high to low. Callers should use
// their actual device ID; the dialer uses a random UUID when no device ID is supplied.
func DeriveSelfSignedID(clientRandomID int64, deviceID string) string {
	input := make([]byte, 8+len(deviceID))
	binary.LittleEndian.PutUint64(input, uint64(clientRandomID))
	copy(input[8:], deviceID)
	digest := md5.Sum(input)

	var id uuid.UUID
	for i := range 8 {
		id[i] = digest[7-i]
		id[8+i] = digest[15-i]
	}
	id[6] = id[6]&0x0f | 0x30
	id[8] = id[8]&0x3f | 0x80
	return id.String()
}
