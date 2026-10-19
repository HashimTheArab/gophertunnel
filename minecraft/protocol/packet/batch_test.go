package packet

import (
	"bytes"
	"testing"
)

func TestBatchBody_SharedFramingAndAdmission(t *testing.T) {
	body := AppendBatchPacket(nil, []byte{1, 2})
	body = AppendBatchPacket(body, []byte{3})
	if !bytes.Equal(body, []byte{2, 1, 2, 1, 3}) {
		t.Fatalf("body = %x", body)
	}
	packets, err := SplitBatch(body, true)
	if err != nil || len(packets) != 2 || cap(packets[0]) != len(packets[0]) {
		t.Fatalf("split = %v, %v", packets, err)
	}
	malformed := append(bytes.Clone(body), 2, 4)
	if packets, err := SplitBatch(malformed, true); err == nil || packets != nil {
		t.Fatalf("malformed body published a prefix: %v, %v", packets, err)
	}
	var many []byte
	for range maximumInBatch + 1 {
		many = AppendBatchPacket(many, []byte{1})
	}
	for _, check := range []bool{false, true} {
		packets, err := SplitBatch(many, check)
		if check && (err == nil || packets != nil) {
			t.Fatal("client packet limit not enforced")
		}
		if !check && (err != nil || len(packets) != maximumInBatch+1) {
			t.Fatalf("server body = %d packets, %v", len(packets), err)
		}
		packets, err = SplitBatch([]byte{0}, check)
		if check && err == nil {
			t.Fatal("client empty-packet check not enforced")
		}
		if !check && (err != nil || len(packets) != 0) {
			t.Fatalf("server empty packet = %v, %v", packets, err)
		}
	}
}
