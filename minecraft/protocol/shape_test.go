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

func TestPrimitiveShapeAttachedEntityIDProtocol2168Wire(t *testing.T) {
	t.Parallel()

	shape := &PrimitiveShape{
		NetworkID:          1,
		AttachedToEntityID: Option(uint64(300)),
		ExtraShapeData:     &LastShape{},
	}
	buf := bytes.NewBuffer(nil)
	shape.Marshal(NewWriter(buf, 0))

	// The attached entity ID carries a runtime ID but keeps the actor unique ID wire type, so 300 goes out as the
	// zigzag varint 600. The eight zero bytes are the preceding absent optional shape fields.
	want := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xd8, 0x04, 0}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("PrimitiveShape wire bytes = %x, want %x", got, want)
	}
}
