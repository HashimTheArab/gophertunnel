package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"testing"
)

func TestPlayerMovement_ExposesPoseWithoutClassifyingTickEchoes(t *testing.T) {
	position, rotation := mgl32.Vec3{1, 2, 3}, mgl32.Vec3{10, 20, 30}
	for _, pk := range []Packet{
		&PlayerAuthInput{Position: position, Pitch: 10, Yaw: 20, HeadYaw: 30},
		&MovePlayer{Position: position, Pitch: 10, Yaw: 20, HeadYaw: 30},
	} {
		movement, ok := pk.(PlayerMovement)
		if !ok {
			t.Fatalf("%T lacks movement pose", pk)
		}
		gotPosition, gotRotation := movement.MovementPose()
		if gotPosition != position || gotRotation != rotation {
			t.Fatalf("%T pose=%v/%v", pk, gotPosition, gotRotation)
		}
	}
	for _, pk := range []Packet{nil, &SetActorMotion{}, &SetActorData{}, &CorrectPlayerMovePrediction{}, &AddActor{}, &Text{}} {
		if _, ok := pk.(PlayerMovement); ok {
			t.Fatalf("%T classified as player movement", pk)
		}
	}
}
