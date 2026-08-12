package packet

import (
	"bytes"
	"testing"
)

func TestFlateCompressionCompressTo(t *testing.T) {
	payload := bytes.Repeat([]byte("minecraft-packet-data:"), 512)
	prefix := []byte{0xfe, 0x01, 0x02}
	buf := bytes.NewBuffer(append([]byte(nil), prefix...))

	if err := FlateCompression.compressTo(buf, payload); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()
	if !bytes.Equal(compressed[:len(prefix)], prefix) {
		t.Fatalf("prefix mismatch: got %#v, want %#v", compressed[:len(prefix)], prefix)
	}
	decompressed, err := FlateCompression.Decompress(compressed[len(prefix):], len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatal("decompressed payload mismatch")
	}
}
