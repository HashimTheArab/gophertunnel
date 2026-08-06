package protocol

import (
	"bytes"
	"testing"
)

func TestTextShapeProtocol2168Wire(t *testing.T) {
	t.Parallel()

	shape := &TextShape{
		Text:             "x",
		UseRotation:      true,
		DepthTest:        true,
		ShowBackfaceText: true,
	}
	buf := bytes.NewBuffer(nil)
	shape.Marshal(NewWriter(buf, 0))

	want := []byte{1, 'x', 1, 0, 1, 0, 1}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("TextShape wire bytes = %x, want %x", got, want)
	}
}

// The attached entity ID carries a runtime ID on the actor unique ID wire type. Writing it
// as an unsigned varint makes the client read the zigzag form, resolve no entity and drop
// every attached shape.
func TestPrimitiveShapeAttachedEntityIDProtocol2168Wire(t *testing.T) {
	t.Parallel()

	shape := &PrimitiveShape{
		NetworkID:          1,
		AttachedToEntityID: Option(int64(300)),
		ExtraShapeData:     &LastShape{},
	}
	buf := bytes.NewBuffer(nil)
	shape.Marshal(NewWriter(buf, 0))

	// 300 goes out as the zigzag varint 600. The eight zero bytes are the preceding absent
	// optional shape fields.
	want := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xd8, 0x04, 0}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("PrimitiveShape wire bytes = %x, want %x", got, want)
	}
}
