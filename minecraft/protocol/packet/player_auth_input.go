package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	PlayModeNormal              protocol.ClientPlayMode = 0
	PlayModeTeaser              protocol.ClientPlayMode = 1
	PlayModeScreen              protocol.ClientPlayMode = 2
	PlayModeViewer              protocol.ClientPlayMode = 3
	PlayModeReality             protocol.ClientPlayMode = 4
	PlayModePlacement           protocol.ClientPlayMode = 5
	PlayModeLivingRoom          protocol.ClientPlayMode = 6
	PlayModeExitLevel           protocol.ClientPlayMode = 7
	PlayModeExitLevelLivingRoom protocol.ClientPlayMode = 8
	ClientPlayModeNumModes      protocol.ClientPlayMode = 9
)

const (
	InputFlagAscend                        protocol.InputData = 0
	InputFlagDescend                       protocol.InputData = 1
	InputFlagNorthJump                     protocol.InputData = 2
	InputFlagJumpDown                      protocol.InputData = 3
	InputFlagSprintDown                    protocol.InputData = 4
	InputFlagChangeHeight                  protocol.InputData = 5
	InputFlagJumping                       protocol.InputData = 6
	InputFlagAutoJumpingInWater            protocol.InputData = 7
	InputFlagSneaking                      protocol.InputData = 8
	InputFlagSneakDown                     protocol.InputData = 9
	InputFlagUp                            protocol.InputData = 10
	InputFlagDown                          protocol.InputData = 11
	InputFlagLeft                          protocol.InputData = 12
	InputFlagRight                         protocol.InputData = 13
	InputFlagUpLeft                        protocol.InputData = 14
	InputFlagUpRight                       protocol.InputData = 15
	InputFlagWantUp                        protocol.InputData = 16
	InputFlagWantDown                      protocol.InputData = 17
	InputFlagWantDownSlow                  protocol.InputData = 18
	InputFlagWantUpSlow                    protocol.InputData = 19
	InputFlagSprinting                     protocol.InputData = 20
	InputFlagAscendBlock                   protocol.InputData = 21
	InputFlagDescendBlock                  protocol.InputData = 22
	InputFlagSneakToggleDown               protocol.InputData = 23
	InputFlagPersistSneak                  protocol.InputData = 24
	InputFlagStartSprinting                protocol.InputData = 25
	InputFlagStopSprinting                 protocol.InputData = 26
	InputFlagStartSneaking                 protocol.InputData = 27
	InputFlagStopSneaking                  protocol.InputData = 28
	InputFlagStartSwimming                 protocol.InputData = 29
	InputFlagStopSwimming                  protocol.InputData = 30
	InputFlagStartJumping                  protocol.InputData = 31
	InputFlagStartGliding                  protocol.InputData = 32
	InputFlagStopGliding                   protocol.InputData = 33
	InputFlagPerformItemInteraction        protocol.InputData = 34
	InputFlagPerformBlockActions           protocol.InputData = 35
	InputFlagPerformItemStackRequest       protocol.InputData = 36
	InputFlagHandledTeleport               protocol.InputData = 37
	InputFlagEmoting                       protocol.InputData = 38
	InputFlagMissedSwing                   protocol.InputData = 39
	InputFlagStartCrawling                 protocol.InputData = 40
	InputFlagStopCrawling                  protocol.InputData = 41
	InputFlagStartFlying                   protocol.InputData = 42
	InputFlagStopFlying                    protocol.InputData = 43
	InputFlagClientAckServerData           protocol.InputData = 44
	InputFlagClientPredictedVehicle        protocol.InputData = 45
	InputFlagPaddlingLeft                  protocol.InputData = 46
	InputFlagPaddlingRight                 protocol.InputData = 47
	InputFlagBlockBreakingDelayEnabled     protocol.InputData = 48
	InputFlagHorizontalCollision           protocol.InputData = 49
	InputFlagVerticalCollision             protocol.InputData = 50
	InputFlagDownLeft                      protocol.InputData = 51
	InputFlagDownRight                     protocol.InputData = 52
	InputFlagStartUsingItem                protocol.InputData = 53
	InputFlagCameraRelativeMovementEnabled protocol.InputData = 54
	InputFlagRotControlledByMoveDirection  protocol.InputData = 55
	InputFlagStartSpinAttack               protocol.InputData = 56
	InputFlagStopSpinAttack                protocol.InputData = 57
	InputFlagIsHotbarTouchOnly             protocol.InputData = 58
	InputFlagJumpReleasedRaw               protocol.InputData = 59
	InputFlagJumpPressedRaw                protocol.InputData = 60
	InputFlagJumpCurrentRaw                protocol.InputData = 61
	InputFlagSneakReleasedRaw              protocol.InputData = 62
	InputFlagSneakPressedRaw               protocol.InputData = 63
	InputFlagSneakCurrentRaw               protocol.InputData = 64
	InputFlagInternalUpdate                protocol.InputData = 65
)

const (
	InputModeUndefined        protocol.InputMode = 0
	InputModeMouse            protocol.InputMode = 1
	InputModeTouch            protocol.InputMode = 2
	InputModeGamePad          protocol.InputMode = 3
	InputModeMotionController protocol.InputMode = 4
	InputModeCount            protocol.InputMode = 5
)

const (
	InteractionModelTouch     protocol.NewInteractionModel = 0
	InteractionModelCrosshair protocol.NewInteractionModel = 1
	InteractionModelClassic   protocol.NewInteractionModel = 2
	InteractionModelCount     protocol.NewInteractionModel = 3
)

// PlayerAuthInput is sent by the client to allow for server authoritative movement. It is used to
// synchronise the player input with the position server-side. The client sends this packet when the
// ServerAuthoritativeMovementMode field in the StartGame packet is set to true, instead of the
// MovePlayer packet. The client will send this packet once every tick.
type PlayerAuthInput struct {
	PlayerRotation mgl32.Vec2
	// Position holds the position that the player reports it has.
	Position mgl32.Vec3
	// MoveVector is a Vec2 that specifies the direction in which the player moved, as a combination of
	// X/Z values which are created using the WASD/controller stick state.
	MoveVector         mgl32.Vec2
	PlayerHeadRotation float32
	// InputData is the set of input flags that together specify the way the player moved last tick. It
	// holds the flags above.
	InputData protocol.Optional[[]protocol.InputData]
	// InputMode specifies the way that the client inputs data to the screen. It is one of the constants
	// that may be found above.
	InputMode protocol.InputMode
	// PlayMode specifies the way that the player is playing. The values it holds, which are rather
	// random, may be found above.
	PlayMode            protocol.ClientPlayMode
	NewInteractionModel protocol.NewInteractionModel
	InteractRotation    mgl32.Vec2
	ClientTick          uint64
	PosDelta            mgl32.Vec3
	ItemUseTransaction  protocol.Optional[protocol.PackedItemUseLegacyInventoryTransaction]
	// ItemStackRequest is sent by the client to change an item in their inventory.
	ItemStackRequest   protocol.Optional[protocol.ItemStackRequestData]
	PlayerBlockActions protocol.Optional[[]protocol.PlayerBlockActionData]
	// VehicleRotation is the rotation of the vehicle that the player is in, if any.
	VehicleRotation protocol.Optional[mgl32.Vec2]
	// ClientPredictedVehicle is the unique ID of the vehicle that the client predicts the player to be
	// in.
	ClientPredictedVehicle protocol.Optional[int64]
	AnalogMoveVector       mgl32.Vec2
	// CameraOrientation is the vector that represents the camera's forward direction which can be used
	// to transform movement to be camera relative.
	CameraOrientation mgl32.Vec3
	// RawMoveVector is the value of MoveVector before it is affected by input permissions, sneaking/fly
	// speeds and isn't normalised for analogue inputs.
	RawMoveVector mgl32.Vec2
}

// Marshal reads or writes PlayerAuthInput using its canonical wire layout.
func (x *PlayerAuthInput) Marshal(io protocol.IO) {
	io.Vec2(&x.PlayerRotation)
	io.Vec3(&x.Position)
	io.Vec2(&x.MoveVector)
	io.Float32(&x.PlayerHeadRotation)
	protocol.OptionalFunc(io, &x.InputData, func(value *[]protocol.InputData) {
		protocol.Slice(io, value)
	})
	x.InputMode.Marshal(io)
	x.PlayMode.Marshal(io)
	x.NewInteractionModel.Marshal(io)
	io.Vec2(&x.InteractRotation)
	io.PlayerInputTick(&x.ClientTick)
	io.Vec3(&x.PosDelta)
	protocol.DoubleOptionalFunc(io, &x.ItemUseTransaction, func(value *protocol.PackedItemUseLegacyInventoryTransaction) {
		value.Marshal(io)
	})
	protocol.DoubleOptionalFunc(io, &x.ItemStackRequest, func(value *protocol.ItemStackRequestData) {
		value.Marshal(io)
	})
	protocol.DoubleOptionalFunc(io, &x.PlayerBlockActions, func(value *[]protocol.PlayerBlockActionData) {
		protocol.SliceLimits(io, value, 0, 100)
	})
	protocol.DoubleOptionalFunc(io, &x.VehicleRotation, io.Vec2)
	protocol.DoubleOptionalFunc(io, &x.ClientPredictedVehicle, io.ActorUniqueID)
	io.Vec2(&x.AnalogMoveVector)
	io.Vec3(&x.CameraOrientation)
	io.Vec2(&x.RawMoveVector)
}

// ID returns the protocol ID for PlayerAuthInput.
func (*PlayerAuthInput) ID() uint32 { return IDPlayerAuthInput }
