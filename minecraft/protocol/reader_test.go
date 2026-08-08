package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestReaderByteSliceRejectsLengthLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteVaruint32(&buf, maxByteSliceLength+1); err != nil {
		t.Fatalf("write length: %v", err)
	}

	r := NewReader(&buf, 0, true)
	err := recoverError(func() {
		var data []byte
		r.ByteSlice(&data)
	})
	if err == nil || !strings.Contains(err.Error(), "slice length was too long") {
		t.Fatalf("expected byte slice length limit error, got %v", err)
	}
}

func TestReaderVaruint32RejectsOverflow(t *testing.T) {
	r := NewReader(bytes.NewBuffer([]byte{0xff, 0xff, 0xff, 0xff, 0x10}), 0, true)
	err := recoverError(func() {
		var v uint32
		r.Varuint32(&v)
	})
	if err == nil || !strings.Contains(err.Error(), "varint overflows integer") {
		t.Fatalf("expected varuint32 overflow error, got %v", err)
	}
}

func TestVaruint32RejectsOverflow(t *testing.T) {
	var v uint32
	err := Varuint32(bytes.NewBuffer([]byte{0xff, 0xff, 0xff, 0xff, 0x10}), &v)
	if err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("expected varuint32 overflow error, got %v", err)
	}
}

func recoverError(f func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recovered.(error)
		}
	}()
	f()
	return nil
}
