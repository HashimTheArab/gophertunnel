package packet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestEncryptedBatchChecksum(t *testing.T) {
	key := [32]byte{1, 2, 3}
	var out bytes.Buffer
	enc := NewEncoder(&out)
	enc.EnableEncryption(key)
	dec := NewDecoder(&out)
	dec.EnableEncryption(key)
	for counter, payload := range [][]byte{{1}, {2, 3, 4}, bytes.Repeat([]byte{5}, 1024)} {
		wire := enc.encrypt.encrypt(append([]byte{header}, payload...))
		dec.encrypt.decrypt(wire[1:])
		data := wire[1:]
		input := binary.LittleEndian.AppendUint64(nil, uint64(counter))
		input = append(input, payload...)
		input = append(input, key[:]...)
		want := sha256.Sum256(input)
		if !bytes.Equal(data[:len(payload)], payload) || !bytes.Equal(data[len(payload):], want[:8]) {
			t.Fatalf("batch %d: payload or checksum mismatch", counter)
		}
		if err := dec.encrypt.verify(data); err != nil {
			t.Fatalf("batch %d: %v", counter, err)
		}
	}
	wire := enc.encrypt.encrypt([]byte{header, 6, 7, 8})
	dec.encrypt.decrypt(wire[1:])
	wire[1] ^= 1
	input := binary.LittleEndian.AppendUint64(nil, dec.encrypt.sendCounter)
	input = append(input, wire[1:len(wire)-8]...)
	input = append(input, key[:]...)
	want := sha256.Sum256(input)
	wantError := fmt.Sprintf("invalid checksum of packet %v: expected %x, got %x", dec.encrypt.sendCounter, want[:8], wire[len(wire)-8:])
	if err := dec.encrypt.verify(wire[1:]); err == nil || err.Error() != wantError {
		t.Fatalf("modified payload error = %v, want %s", err, wantError)
	}
}

// BenchmarkBatchChecksum measures checksum allocations independently of compression and packet marshaling.
func BenchmarkBatchChecksum(b *testing.B) {
	key := [32]byte{1, 2, 3}
	b.Run("send", func(b *testing.B) {
		var out bytes.Buffer
		enc := NewEncoder(&out)
		enc.EnableEncryption(key)
		data := make([]byte, 1025, 1033)
		data[0] = header
		b.ReportAllocs()
		for b.Loop() {
			enc.encrypt.encrypt(data)
		}
	})
	b.Run("verify", func(b *testing.B) {
		data := make([]byte, 1024, 1032)
		input := make([]byte, 8)
		input = append(input, data...)
		input = append(input, key[:]...)
		sum := sha256.Sum256(input)
		data = append(data, sum[:8]...)
		var out bytes.Buffer
		dec := NewDecoder(&out)
		dec.EnableEncryption(key)
		b.ReportAllocs()
		for b.Loop() {
			dec.encrypt.sendCounter = 0
			if err := dec.encrypt.verify(data); err != nil {
				b.Fatal(err)
			}
		}
	})
}
