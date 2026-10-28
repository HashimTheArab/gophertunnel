package nbt

import (
	"bytes"
	"io"
	"testing"
)

// Every fixed-width or length-prefixed read must fail one byte short instead of returning stale or zero bytes.
func TestEncodingReadsRejectTruncation(t *testing.T) {
	encodings := []struct {
		name string
		e    Encoding
	}{
		{"little endian", LittleEndian},
		{"big endian", BigEndian},
		{"network little endian", NetworkLittleEndian},
		{"network big endian", NetworkBigEndian},
	}
	reads := []struct {
		name  string
		write func(Encoding, *offsetWriter) error
		read  func(Encoding, *offsetReader) error
	}{
		{"int16", func(e Encoding, w *offsetWriter) error { return e.WriteInt16(w, -12345) },
			func(e Encoding, r *offsetReader) error { _, err := e.Int16(r); return err }},
		{"int32", func(e Encoding, w *offsetWriter) error { return e.WriteInt32(w, -123456789) },
			func(e Encoding, r *offsetReader) error { _, err := e.Int32(r); return err }},
		{"int64", func(e Encoding, w *offsetWriter) error { return e.WriteInt64(w, -1234567890123) },
			func(e Encoding, r *offsetReader) error { _, err := e.Int64(r); return err }},
		{"float32", func(e Encoding, w *offsetWriter) error { return e.WriteFloat32(w, 1.5) },
			func(e Encoding, r *offsetReader) error { _, err := e.Float32(r); return err }},
		{"float64", func(e Encoding, w *offsetWriter) error { return e.WriteFloat64(w, -2.25) },
			func(e Encoding, r *offsetReader) error { _, err := e.Float64(r); return err }},
		{"string", func(e Encoding, w *offsetWriter) error { return e.WriteString(w, "minecraft:stone") },
			func(e Encoding, r *offsetReader) error { _, err := e.String(r); return err }},
		{"int32 slice", func(e Encoding, w *offsetWriter) error { return writeAll(w, e.WriteInt32, 2, 300, -70000) },
			func(e Encoding, r *offsetReader) error { _, err := e.Int32Slice(r); return err }},
		{"int64 slice", func(e Encoding, w *offsetWriter) error {
			if err := e.WriteInt32(w, 2); err != nil {
				return err
			}
			return writeAll(w, e.WriteInt64, 300, -1234567890123)
		}, func(e Encoding, r *offsetReader) error { _, err := e.Int64Slice(r); return err }},
	}
	sources := []struct {
		name string
		wrap func([]byte) io.Reader
	}{
		{"buffer", func(b []byte) io.Reader { return bytes.NewBuffer(b) }},
		{"plain reader", func(b []byte) io.Reader { return struct{ io.Reader }{bytes.NewReader(b)} }},
	}
	for _, enc := range encodings {
		for _, read := range reads {
			buf := new(bytes.Buffer)
			if err := read.write(enc.e, &offsetWriter{Writer: buf, WriteByte: buf.WriteByte}); err != nil {
				t.Fatalf("%s %s: write: %v", enc.name, read.name, err)
			}
			full := buf.Bytes()
			for _, src := range sources {
				if err := read.read(enc.e, newOffsetReader(src.wrap(full))); err != nil {
					t.Errorf("%s %s from %s: full read failed: %v", enc.name, read.name, src.name, err)
				}
				if err := read.read(enc.e, newOffsetReader(src.wrap(full[:len(full)-1]))); err == nil {
					t.Errorf("%s %s from %s: read of %d/%d bytes succeeded", enc.name, read.name, src.name, len(full)-1, len(full))
				}
			}
		}
	}
}

// Next on a reader without its own Next must not pad a short read to the requested length.
func TestOffsetReaderNextFallbackReturnsOnlyReadBytes(t *testing.T) {
	r := newOffsetReader(struct{ io.Reader }{bytes.NewReader([]byte{1, 2})})
	if got := r.Next(3); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("Next(3) = %v, want [1 2]", got)
	}
}

// writeAll writes each value in order and returns the first error.
func writeAll[T any](w *offsetWriter, write func(*offsetWriter, T) error, values ...T) error {
	for _, v := range values {
		if err := write(w, v); err != nil {
			return err
		}
	}
	return nil
}
