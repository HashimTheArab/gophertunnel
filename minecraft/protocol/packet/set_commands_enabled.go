package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// SetCommandsEnabled is sent by the server to enable or disable the ability to execute commands for
// the client. If disabled, the client itself will stop the execution of commands.
type SetCommandsEnabled struct {
	// CommandsEnabled defines if the commands should be enabled, or if false, disabled.
	Enabled bool
}

// Marshal reads or writes SetCommandsEnabled using its canonical wire layout.
func (x *SetCommandsEnabled) Marshal(io protocol.IO) {
	io.Bool(&x.Enabled)
}

// ID returns the protocol ID for SetCommandsEnabled.
func (*SetCommandsEnabled) ID() uint32 { return IDSetCommandsEnabled }
