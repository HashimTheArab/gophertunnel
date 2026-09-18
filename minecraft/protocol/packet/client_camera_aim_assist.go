package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	ClientCameraAimAssistActionSet   protocol.ClientCameraAimAssistAction = 0
	ClientCameraAimAssistActionClear protocol.ClientCameraAimAssistAction = 1
)

// ClientCameraAimAssist is sent by the server to send a player animation from one player to all
// viewers of that player. It is used for a couple of actions, such as arm swimming and critical
// hits.
type ClientCameraAimAssist struct {
	// CameraPresetID is the identifier of the preset to use which was previously defined in the
	// CameraAimAssistPresets packet.
	PresetID string
	// Action is the action to perform with the aim assist. It is one of the constants above.
	Action protocol.ClientCameraAimAssistAction
	// AllowAimAssist specifies the client can use aim assist or not.
	AllowAimAssist bool
}

// Marshal reads or writes ClientCameraAimAssist using its canonical wire layout.
func (x *ClientCameraAimAssist) Marshal(io protocol.IO) {
	io.String(&x.PresetID)
	x.Action.Marshal(io)
	io.Bool(&x.AllowAimAssist)
}

// ID returns the protocol ID for ClientCameraAimAssist.
func (*ClientCameraAimAssist) ID() uint32 { return IDClientCameraAimAssist }
