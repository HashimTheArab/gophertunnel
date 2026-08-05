package protocol

import (
	"bytes"
	"encoding/binary"
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

	for _, attachedID := range []int64{300, -8589933873} {
		shape := &PrimitiveShape{
			NetworkID:          1,
			AttachedToEntityID: Option(attachedID),
			ExtraShapeData:     &LastShape{},
		}
		buf := bytes.NewBuffer(nil)
		shape.Marshal(NewWriter(buf, 0))

		// Protocol 2168 writes the signed actor unique ID's bit pattern as an
		// unsigned varint. The eight zero bytes are the preceding absent optional
		// shape fields.
		want := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		want = binary.AppendUvarint(want, uint64(attachedID))
		want = append(want, 0)
		if got := buf.Bytes(); !bytes.Equal(got, want) {
			t.Errorf("PrimitiveShape attached ID %d wire bytes = %x, want %x", attachedID, got, want)
		}
	}
}
