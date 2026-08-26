package nbt

import (
	"bytes"
	"io"
	"reflect"
)

// RawMessage holds one encoded NBT value. Its contents are immutable through
// the public API, so a message may be forwarded without re-encoding it.
type RawMessage struct {
	data []byte
}

// NewRawMessage returns a message that owns a copy of data.
func NewRawMessage(data []byte) RawMessage {
	return RawMessage{data: bytes.Clone(data)}
}

// Bytes returns a copy of the encoded NBT value.
func (m RawMessage) Bytes() []byte {
	return bytes.Clone(m.data)
}

// ValidateCompound reports an error unless the message root is a compound, or
// a lone TAG_End when allowZero is true.
func (m RawMessage) ValidateCompound(allowZero bool) error {
	if len(m.data) == 0 {
		return BufferOverrunError{Op: "ReadTag"}
	}
	t := tagType(m.data[0])
	if t == tagStruct || (t == tagEnd && allowZero) {
		return nil
	}
	if !t.IsValid() {
		return UnknownTagError{Op: "Compound", TagType: t}
	}
	return UnexpectedTagError{TagType: t}
}

// WriteTo writes the encoded NBT value without materialising it.
func (m RawMessage) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(m.data)
	if err == nil && n != len(m.data) {
		err = io.ErrShortWrite
	}
	return int64(n), err
}

// Unmarshal decodes the complete message into v using encoding. A lone
// TAG_End is materialised as an empty map, matching protocol NBT decoding.
func (m RawMessage) Unmarshal(v any, encoding Encoding) error {
	decoder := NewDecoderWithEncoding(bytes.NewBuffer(m.data), encoding)
	decoder.AllowZero = true
	return decoder.Decode(v)
}

// DecodeFields decodes only the named top-level compound fields. Values below
// selected fields are decoded normally; every other value is validated and
// skipped without building its Go representation.
func (m RawMessage) DecodeFields(encoding Encoding, fields ...string) (map[string]any, error) {
	decoder := NewDecoderWithEncoding(bytes.NewBuffer(m.data), encoding)
	decoder.AllowZero = true
	t, _, err := decoder.tag()
	if err != nil {
		return nil, err
	}
	if t == tagEnd {
		return map[string]any{}, nil
	}
	if t != tagStruct {
		return nil, UnexpectedTagError{Off: decoder.r.off, TagType: t}
	}

	values := make(map[string]any, len(fields))
	decoder.depth++
	defer func() { decoder.depth-- }()
	for {
		nestedType, name, err := decoder.tag()
		if err != nil {
			return nil, err
		}
		if !nestedType.IsValid() {
			return nil, UnknownTagError{Off: decoder.r.off, Op: "Fields", TagType: nestedType}
		}
		if nestedType == tagEnd {
			return values, nil
		}
		if rawMessageFieldSelected(name, fields) {
			var value any
			if err := decoder.unmarshalTag(reflect.ValueOf(&value).Elem(), nestedType, name); err != nil {
				return nil, err
			}
			values[name] = value
			continue
		}
		if err := decoder.skipTag(nestedType); err != nil {
			return nil, err
		}
	}
}

// ReadRaw reads and validates one NBT value. The returned message owns its
// bytes, so callers may reuse the input buffer immediately.
func ReadRaw(r interface {
	io.Reader
	io.ByteReader
}, encoding Encoding, allowZero bool) (RawMessage, error) {
	if source, ok := r.(*bytes.Buffer); ok {
		before := source.Bytes()
		decoder := NewDecoderWithEncoding(r, encoding)
		decoder.AllowZero = allowZero
		if err := decoder.Skip(); err != nil {
			return RawMessage{}, err
		}
		consumed := len(before) - len(source.Bytes())
		return NewRawMessage(before[:consumed:consumed]), nil
	}

	capture := &rawCaptureReader{reader: r}
	decoder := NewDecoderWithEncoding(capture, encoding)
	decoder.AllowZero = allowZero
	if err := decoder.Skip(); err != nil {
		return RawMessage{}, err
	}
	return RawMessage{data: capture.data.Bytes()}, nil
}

// Skip validates and consumes the next NBT value without materialising it.
func (d *Decoder) Skip() error {
	t, _, err := d.tag()
	if err != nil {
		return err
	}
	if t == tagEnd && d.AllowZero {
		return nil
	}
	return d.skipTag(t)
}

// skipTag validates and consumes the payload of t without retaining it.
func (d *Decoder) skipTag(t tagType) error {
	switch t {
	default:
		return UnknownTagError{Off: d.r.off, Op: "Skip", TagType: t}
	case tagEnd:
		return UnexpectedTagError{Off: d.r.off, TagType: t}
	case tagByte:
		if _, err := d.r.ReadByte(); err != nil {
			return BufferOverrunError{Op: "Byte"}
		}
	case tagInt16:
		_, err := d.Encoding.Int16(d.r)
		return err
	case tagInt32:
		_, err := d.Encoding.Int32(d.r)
		return err
	case tagInt64:
		_, err := d.Encoding.Int64(d.r)
		return err
	case tagFloat32:
		_, err := d.Encoding.Float32(d.r)
		return err
	case tagFloat64:
		_, err := d.Encoding.Float64(d.r)
		return err
	case tagString:
		return d.skipString()
	case tagByteArray:
		length, err := d.Encoding.Int32(d.r)
		if err != nil {
			return err
		}
		return d.skipBytes(length, "ByteArray")
	case tagInt32Array:
		length, err := d.Encoding.Int32(d.r)
		if err != nil {
			return err
		}
		if length < 0 {
			return BufferOverrunError{Op: "Int32Array"}
		}
		for range length {
			if _, err := d.Encoding.Int32(d.r); err != nil {
				return err
			}
		}
	case tagInt64Array:
		length, err := d.Encoding.Int32(d.r)
		if err != nil {
			return err
		}
		if length < 0 {
			return BufferOverrunError{Op: "Int64Array"}
		}
		for range length {
			if _, err := d.Encoding.Int64(d.r); err != nil {
				return err
			}
		}
	case tagSlice:
		d.depth++
		defer func() { d.depth-- }()
		elementTypeByte, err := d.r.ReadByte()
		if err != nil {
			return BufferOverrunError{Op: "Slice"}
		}
		elementType := tagType(elementTypeByte)
		if !elementType.IsValid() {
			return UnknownTagError{Off: d.r.off, Op: "Slice", TagType: elementType}
		}
		length, err := d.Encoding.Int32(d.r)
		if err != nil {
			return err
		}
		if length < 0 {
			return BufferOverrunError{Op: "Slice"}
		}
		for range length {
			if err := d.skipTag(elementType); err != nil {
				return err
			}
		}
	case tagStruct:
		d.depth++
		defer func() { d.depth-- }()
		for {
			nestedType, err := d.skipNamedTag()
			if err != nil {
				return err
			}
			if !nestedType.IsValid() {
				return UnknownTagError{Off: d.r.off, Op: "Compound", TagType: nestedType}
			}
			if nestedType == tagEnd {
				return nil
			}
			if err := d.skipTag(nestedType); err != nil {
				return err
			}
		}
	}
	return nil
}

// skipBytes consumes length bytes without retaining them.
func (d *Decoder) skipBytes(length int32, op string) error {
	if length < 0 {
		return BufferOverrunError{Op: op}
	}
	if err := d.checkRemaining(int(length), op); err != nil {
		return err
	}
	if _, ok := d.r.Reader.(interface{ Next(int) []byte }); ok {
		if data := d.r.Next(int(length)); len(data) != int(length) {
			return BufferOverrunError{Op: op}
		}
		return nil
	}
	remaining := int(length)
	var buf [4096]byte
	for remaining > 0 {
		n := min(remaining, len(buf))
		if _, err := io.ReadFull(d.r, buf[:n]); err != nil {
			return BufferOverrunError{Op: op}
		}
		remaining -= n
	}
	return nil
}

// skipString consumes an encoded NBT string without allocating its contents.
func (d *Decoder) skipString() error {
	if encoding, ok := d.Encoding.(networkLittleEndian); ok {
		length, err := encoding.stringLength(d.r)
		if err != nil {
			return err
		}
		if length > maxStringSize {
			return InvalidStringError{N: uint(length), Off: d.r.off, Err: errStringTooLong}
		}
		return d.skipBytes(int32(length), "String")
	}
	length, err := d.Encoding.Int16(d.r)
	if err != nil {
		return BufferOverrunError{Op: "String"}
	}
	return d.skipBytes(int32(length), "String")
}

// skipNamedTag consumes a nested tag header without allocating its name.
func (d *Decoder) skipNamedTag() (tagType, error) {
	if d.depth >= maximumNestingDepth {
		return 0, MaximumDepthReachedError{}
	}
	if d.r.off >= maximumNetworkOffset && d.Encoding == NetworkLittleEndian {
		return 0, MaximumBytesReadError{}
	}
	tagTypeByte, err := d.r.ReadByte()
	if err != nil {
		return 0, BufferOverrunError{Op: "ReadTag"}
	}
	t := tagType(tagTypeByte)
	if t != tagEnd {
		if err := d.skipString(); err != nil {
			return 0, err
		}
	}
	return t, nil
}

// rawMessageFieldSelected reports whether name is one of the requested fields.
func rawMessageFieldSelected(name string, fields []string) bool {
	for _, field := range fields {
		if name == field {
			return true
		}
	}
	return false
}

type rawCaptureReader struct {
	reader interface {
		io.Reader
		io.ByteReader
	}
	data bytes.Buffer
}

// Read captures bytes read from the wrapped reader.
func (r *rawCaptureReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	_, _ = r.data.Write(p[:n])
	return n, err
}

// ReadByte captures one byte read from the wrapped reader.
func (r *rawCaptureReader) ReadByte() (byte, error) {
	b, err := r.reader.ReadByte()
	if err == nil {
		_ = r.data.WriteByte(b)
	}
	return b, err
}
