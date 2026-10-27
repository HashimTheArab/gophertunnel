package protocol

import (
	"bytes"
	"image/color"
	"strings"
	"testing"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/google/uuid"
)

func TestReaderByteSliceRejectsLengthLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteVaruint32(&buf, maxByteSliceLength+1); err != nil {
		t.Fatalf("write length: %v", err)
	}

	r := NewReader(&buf, 0, true)
	err := recoverReaderError(func() {
		var data []byte
		r.ByteSlice(&data)
	})
	if err == nil || !strings.Contains(err.Error(), "slice length was too long") {
		t.Fatalf("expected byte slice length limit error, got %v", err)
	}
}

func TestReaderAllowsEmptyTerminalStringAndByteSlice(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(*Reader)
	}{
		{name: "string", read: func(r *Reader) { var value string; r.String(&value) }},
		{name: "byte slice", read: func(r *Reader) { var value []byte; r.ByteSlice(&value) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteVaruint32(&buf, 0); err != nil {
				t.Fatalf("write empty length: %v", err)
			}
			if err := recoverReaderError(func() { test.read(NewReader(bytes.NewReader(buf.Bytes()), 0, false)) }); err != nil {
				t.Fatalf("empty terminal %s panicked: %v", test.name, err)
			}
		})
	}
}

// A fixed-width read one byte short must fail rather than keep stale scratch bytes.
func TestReaderFixedWidthReadsRejectTruncation(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
		read func(*Reader)
	}{
		{name: "uint16", size: 2, read: func(r *Reader) { var v uint16; r.Uint16(&v) }},
		{name: "int16", size: 2, read: func(r *Reader) { var v int16; r.Int16(&v) }},
		{name: "uint32", size: 4, read: func(r *Reader) { var v uint32; r.Uint32(&v) }},
		{name: "int32", size: 4, read: func(r *Reader) { var v int32; r.Int32(&v) }},
		{name: "be int32", size: 4, read: func(r *Reader) { var v int32; r.BEInt32(&v) }},
		{name: "uint64", size: 8, read: func(r *Reader) { var v uint64; r.Uint64(&v) }},
		{name: "int64", size: 8, read: func(r *Reader) { var v int64; r.Int64(&v) }},
		{name: "float32", size: 4, read: func(r *Reader) { var v float32; r.Float32(&v) }},
		{name: "float64", size: 8, read: func(r *Reader) { var v float64; r.Float64(&v) }},
		{name: "vec2", size: 8, read: func(r *Reader) { var v mgl32.Vec2; r.Vec2(&v) }},
		{name: "vec3", size: 12, read: func(r *Reader) { var v mgl32.Vec3; r.Vec3(&v) }},
		{name: "rgb", size: 12, read: func(r *Reader) { var v color.RGBA; r.RGB(&v) }},
		{name: "rgba", size: 4, read: func(r *Reader) { var v color.RGBA; r.RGBA(&v) }},
		{name: "be argb", size: 4, read: func(r *Reader) { var v color.RGBA; r.BEARGB(&v) }},
		{name: "uuid", size: 16, read: func(r *Reader) { var v uuid.UUID; r.UUID(&v) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0x7f}, test.size)
			if err := recoverReaderError(func() { test.read(NewReader(bytes.NewBuffer(data), 0, true)) }); err != nil {
				t.Fatalf("full read failed: %v", err)
			}
			if err := recoverReaderError(func() { test.read(NewReader(bytes.NewBuffer(data[:test.size-1]), 0, true)) }); err == nil {
				t.Fatalf("read of %d/%d bytes succeeded", test.size-1, test.size)
			}
		})
	}
}

func recoverReaderError(f func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recovered.(error)
		}
	}()
	f()
	return nil
}
