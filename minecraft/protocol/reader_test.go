package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestReaderVarintsRejectOverlongEncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		read func(*Reader)
	}{
		{
			name: "varint32",
			data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0},
			read: func(r *Reader) {
				var v int32
				r.Varint32(&v)
			},
		},
		{
			name: "varuint32",
			data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0},
			read: func(r *Reader) {
				var v uint32
				r.Varuint32(&v)
			},
		},
		{
			name: "varint64",
			data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0},
			read: func(r *Reader) {
				var v int64
				r.Varint64(&v)
			},
		},
		{
			name: "varuint64",
			data: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0},
			read: func(r *Reader) {
				var v uint64
				r.Varuint64(&v)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := NewReader(bytes.NewBuffer(tt.data), 0, false)
			err := readerPanic(func() {
				tt.read(r)
			})
			if !errors.Is(err, errVarIntOverflow) {
				t.Fatalf("expected varint overflow, got %v", err)
			}
		})
	}
}

func readerPanic(f func()) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err, _ = v.(error)
		}
	}()
	f()
	return nil
}
