package protocol

import (
	"bytes"
	"image/color"
	"reflect"
	"testing"

	"github.com/go-gl/mathgl/mgl32"
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

// The attached entity ID is an actor unique ID. Writing it as an unsigned varint makes the
// client read the zigzag form, resolve no entity and drop every attached shape.
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

// Every registered shape data type clones to an equal, detached value and
// compares unequal to any other type; the registry, not a hand list, decides
// which types take part.
func TestShapeDataCloneAndEqualCoverEveryRegisteredType(t *testing.T) {
	t.Parallel()

	var registered []ShapeData
	for shapeDataType := uint32(0); ; shapeDataType++ {
		var data ShapeData
		if !lookupShapeData(shapeDataType, &data) {
			break
		}
		registered = append(registered, data)
	}
	if len(registered) == 0 {
		t.Fatal("no shape data types registered")
	}
	for i, data := range registered {
		clone := data.Clone()
		// Zero-size values share one address, so identity only matters for data that has any.
		if clone == data && reflect.TypeOf(data).Elem().Size() > 0 {
			t.Fatalf("%T.Clone returned the receiver", data)
		}
		if !data.Equal(clone) || !clone.Equal(data) {
			t.Fatalf("%T is not equal to its clone", data)
		}
		for j, other := range registered {
			if i != j && data.Equal(other) {
				t.Fatalf("%T reported equal to %T", data, other)
			}
		}
	}
}

func TestShapeDataEqualComparesValues(t *testing.T) {
	t.Parallel()

	a := &TextShape{Text: "a", DepthTest: true}
	if !a.Equal(&TextShape{Text: "a", DepthTest: true}) {
		t.Fatal("equal values reported unequal")
	}
	if a.Equal(&TextShape{Text: "b", DepthTest: true}) {
		t.Fatal("different text reported equal")
	}
}

func TestPrimitiveShapeEqualAndClone(t *testing.T) {
	t.Parallel()

	shape := PrimitiveShape{
		NetworkID: 7, Type: Option(PrimitiveShapeLine), Colour: Option(color.RGBA{R: 255, A: 255}),
		ExtraShapeData: &LineShape{LineEndLocation: mgl32.Vec3{1, 2, 3}},
	}
	clone := shape.Clone()
	if clone.ExtraShapeData == shape.ExtraShapeData {
		t.Fatal("clone shares shape data with the original")
	}
	if !shape.Equal(clone) {
		t.Fatal("clone is not equal to the original")
	}
	changed := clone
	changed.NetworkID = 8
	if shape.Equal(changed) {
		t.Fatal("different network ID reported equal")
	}
	changed = clone.Clone()
	changed.ExtraShapeData = &LineShape{LineEndLocation: mgl32.Vec3{9, 9, 9}}
	if shape.Equal(changed) {
		t.Fatal("different shape data reported equal")
	}
	changed = clone
	changed.ExtraShapeData = nil
	if shape.Equal(changed) || changed.Equal(shape) {
		t.Fatal("missing shape data reported equal to present shape data")
	}
	if !changed.Equal(changed) {
		t.Fatal("nil shape data is not equal to itself")
	}
}
