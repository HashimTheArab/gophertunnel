package auth

type Device struct {
	// ClientID is the client id used to authenticate with minecraft.
	ClientID string
	// DeviceType is the corresponding type given to minecraft, it needs to match the client id.
	DeviceType string
	Version    string
}

var DeviceAndroid = Device{ClientID: "0000000048183522", DeviceType: "Android", Version: "10"}
