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

func recoverReaderError(f func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = recovered.(error)
		}
	}()
	f()
	return nil
}
