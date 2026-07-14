package nbt

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecoderRejectsImpossibleByteLengthsBeforeReadingPayload(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		out  func() any
		op   string
	}{
		{
			name: "byte array",
			data: []byte{byte(tagByteArray), 0, 0, 4, 0, 0, 0, 0xff},
			out:  func() any { return new([4]byte) },
			op:   "ByteArray",
		},
		{
			name: "byte list",
			data: []byte{byte(tagSlice), 0, 0, byte(tagByte), 4, 0, 0, 0, 0xff},
			out:  func() any { return new([]byte) },
			op:   "ByteSlice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tt.data)
			err := NewDecoderWithEncoding(buf, LittleEndian).Decode(tt.out())
			var overrun BufferOverrunError
			if !errors.As(err, &overrun) {
				t.Fatalf("Decode() error = %v, want BufferOverrunError", err)
			}
			if overrun.Op != tt.op {
				t.Fatalf("BufferOverrunError.Op = %q, want %q", overrun.Op, tt.op)
			}
			if got := buf.Len(); got != 1 {
				t.Fatalf("remaining payload bytes = %d, want 1", got)
			}
		})
	}
}
