package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ScriptMessage is used to communicate custom messages from the client to the server, or from the server to
// the client. While the name may suggest this packet is used for the discontinued scripting API, it is likely
// instead for the GameTest framework.
type ScriptMessage struct {
	Identifier string
	Data       []byte
}

// Marshal reads or writes ScriptMessage using its canonical wire layout.
func (x *ScriptMessage) Marshal(io protocol.IO) {
	io.String(&x.Identifier)
	io.Bytes(&x.Data)
}

// ID returns the protocol ID for ScriptMessage.
func (*ScriptMessage) ID() uint32 { return IDScriptMessage }
