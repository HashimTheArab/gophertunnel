package auth

type Device struct {
	// ClientID is the client id used to authenticate with minecraft.
	ClientID string
	// DeviceType is the corresponding type given to minecraft.
	DeviceType string
	Version    string
	TitleID    string
	UserAgent  string
}

var (
	DeviceAndroid = Device{
		DeviceType: "Android",
		ClientID:   "0000000048183522",
		TitleID:    "1739947436",
		Version:    "8.0.0",
		UserAgent:  "XAL Android 2020.07.20200714.000",
	}
	DeviceIOS = Device{
		DeviceType: "iOS",
		ClientID:   "000000004c17c01a", // may be 000000004C17C01A
		TitleID:    "1810924247",
		Version:    "15.6.1",
		UserAgent:  "XAL iOS 2021.11.20211021.000",
	}
	DeviceWin32 = Device{
		DeviceType: "Win32",
		ClientID:   "0000000040159362",
		TitleID:    "896928775",
		Version:    "10.0.25398.4909",
		UserAgent:  "XAL Win32 2021.11.20220411.002",
	}
	DeviceNintendo = Device{
		DeviceType: "Nintendo",
		ClientID:   "00000000441cc96b",
		TitleID:    "2047319603",
		Version:    "0.0.0",
		UserAgent:  "XAL",
	}
	DevicePlaystation = Device{
		DeviceType: "Playstation",
		ClientID:   "000000004827c78e",
		TitleID:    "idk",
		Version:    "10.0.0",
		UserAgent:  "XAL",
	}
)
