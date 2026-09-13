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

func recoverReaderError(f func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recovered.(error)
		}
	}()
	f()
	return nil
}
