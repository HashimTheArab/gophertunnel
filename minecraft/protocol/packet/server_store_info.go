// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ServerStoreInfo is sent by the server to provide the client with a store entry point. Like the
// ShowStoreOffer packet, this only has an effect on partnered servers.
type ServerStoreInfo struct {
	// ClientStoreEntryPointConfiguration is the store info to set, or nothing to fall back to the
	// default.
	StoreInfo protocol.Optional[protocol.ServerConfigurationClientStoreEntryPointConfiguration]
}

// Marshal reads or writes ServerStoreInfo using its canonical wire layout.
func (x *ServerStoreInfo) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &x.StoreInfo)
}

// ID returns the protocol ID for ServerStoreInfo.
func (*ServerStoreInfo) ID() uint32 { return IDServerStoreInfo }
