// Package device describes the device a client claims at login. A server can compare the claimed
// DeviceOS with the platform of the Xbox title the player signed in as, so the two must agree.
package device

import (
	"math/rand/v2"
	"slices"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Profile is the device a client claims at login. Keep one per install: a device that changes on
// every join looks like a different player to a server.
type Profile struct {
	OS    protocol.DeviceOS `json:"os"`
	Model string            `json:"model"`
	ID    login.DeviceID    `json:"id"`
}

// New returns a profile for os with a realistic model and a device ID in the format os uses.
func New(os protocol.DeviceOS) Profile {
	profile := Profile{OS: os, ID: login.ClientData{DeviceOS: os}.ExpectedDeviceIDFormat().Generate()}
	if choices := Models(os); len(choices) != 0 {
		profile.Model = choices[rand.IntN(len(choices))]
	}
	return profile
}

// Models returns the device models New chooses from for os; Win32 shares the Windows models.
func Models(os protocol.DeviceOS) []string {
	if os == protocol.DeviceWin32 {
		os = protocol.DeviceWin10
	}
	return slices.Clone(models[os])
}

// Valid reports whether p names a model and device ID format that os reports.
func (p Profile) Valid() bool {
	format := login.ClientData{DeviceOS: p.OS}.ExpectedDeviceIDFormat()
	if format != login.DeviceIDFormatInvalid && p.ID.Format() != format {
		return false
	}
	choices := Models(p.OS)
	return len(choices) == 0 && p.Model == "" || slices.Contains(choices, p.Model)
}

// Apply claims p's device, and the input mode its platform defaults to, in data.
func (p Profile) Apply(data *login.ClientData) {
	data.DeviceOS = p.OS
	data.DeviceModel = p.Model
	data.DeviceID = p.ID
	data.DefaultInputMode = DefaultInputMode(p.OS)
}

// DefaultInputMode returns the input mode a client on os starts in.
func DefaultInputMode(os protocol.DeviceOS) int {
	switch os {
	case protocol.DeviceOSX, protocol.DeviceWin10, protocol.DeviceWin32, protocol.DeviceTVOS, protocol.DeviceLinux:
		return packet.InputModeMouse
	case protocol.DeviceOrbis, protocol.DeviceNX, protocol.DeviceXBOX:
		return packet.InputModeGamePad
	default:
		return packet.InputModeTouch
	}
}

// AuthConfig returns the Xbox title configuration a client on os signs in with; ok is false for an
// os whose sign-in is not supported here.
func AuthConfig(os protocol.DeviceOS) (config auth.Config, ok bool) {
	switch os {
	case protocol.DeviceAndroid:
		return auth.AndroidConfig, true
	}
	return auth.Config{}, false
}

// models are realistic device model strings each OS reports, in the format its client sends.
var models = map[protocol.DeviceOS][]string{
	protocol.DeviceAndroid: {
		"GOOGLE Pixel 10 Pro", "GOOGLE Pixel 9 Pro", "GOOGLE Pixel 9",
		"GOOGLE Pixel 8 Pro", "GOOGLE Pixel 8", "SAMSUNG SM-S938B",
		"SAMSUNG SM-S928B", "SAMSUNG SM-S926B", "SAMSUNG SM-S921B",
		"SAMSUNG SM-S918B", "SAMSUNG SM-S916B", "SAMSUNG SM-S911B",
		"SAMSUNG SM-J327T1", "SAMSUNG SM-A107F", "SAMSUNG SM-A530x", "SAMSUNG SM-A730x",
		"SAMSUNG SM-A810x", "SAMSUNG SM-A7100", "SAMSUNG SM-A710F", "SAMSUNG SM-A710FD",
		"SAMSUNG SM-A710M", "SAMSUNG SM-A710Y", "SAMSUNG SM-A5100", "SAMSUNG SM-A510F",
		"SAMSUNG SM-A510FD", "SAMSUNG SM-A510M", "SAMSUNG SM-A510Y", "SAMSUNG SM-A310F",
		"SAMSUNG SM-A310M", "SAMSUNG-SM-G900A", "SAMSUNG SAMSUNG-SM-G900A", "SAMSUNG SM-G920F",
		"SAMSUNG SM-G930T", "SAMSUNG SM-G930F", "SAMSUNG SM-G930FD", "SAMSUNG SM-G9300",
		"SAMSUNG SM-G930A", "SAMSUNG SM-G930V", "SAMSUNG SM-G930AZ", "SAMSUNG SM-G930S",
		"SAMSUNG SM-G930K", "SAMSUNG SM-G930W8", "SAMSUNG SM-G935F", "SAMSUNG SM-G935FD",
		"SAMSUNG SM-G9350", "SAMSUNG SM-G935A", "SAMSUNG SM-G935V", "SAMSUNG SM-G935U",
		"SAMSUNG SM-G935S", "SAMSUNG SM-G935K", "SAMSUNG SM-G935W8", "SAMSUNG SC-02H",
		"SAMSUNG SM-N950x", "SAMSUNG SM-G950x", "SAMSUNG SM-G950U", "SAMSUNG SM-G955x",
		"SAMSUNG SM-G960U", "SAMSUNG SM-T280", "SAMSUNG SM-T350", "SAMSUNG SM-T580",
		"SAMSUNG SM-T820", "TCL 5065D", "LGE LG-K373", "LGE LG-V495", "LGE LGMP450",
		"SONY E2303", "MOTOROLA MotoE2(4G-LTE)",
	},
	protocol.DeviceIOS: {
		"iPhone18,1", "iPhone17,5", "iPhone17,4", "iPhone17,3", "iPhone17,2",
		"iPhone17,1", "iPhone16,2", "iPhone16,1", "iPad16,4", "iPad16,3",
		"iPad15,8", "iPad15,7", "iPad14,6", "iPad14,5",
		"iPhone4,1", "iPhone5,1", "iPhone5,2", "iPhone5,3", "iPhone5,4",
		"iPhone6,1", "iPhone6,2", "iPhone7,2", "iPhone7,1", "iPhone8,1",
		"iPhone8,2", "iPhone8,4", "iPhone9,1", "iPhone9,3", "iPhone9,2",
		"iPhone9,4", "iPhone10,1", "iPhone10,4", "iPhone10,2", "iPhone10,5",
		"iPhone10,3", "iPhone10,6", "iPod4,1", "iPod5,1", "iPod7,1",
		"iPad2,5", "iPad2,6", "iPad2,7", "iPad4,4", "iPad4,5", "iPad4,6",
		"iPad4,7", "iPad4,8", "iPad4,9", "iPad5,1", "iPad5,1", "iPad2,1",
		"iPad2,2", "iPad2,3", "iPad2,4", "iPad3,1", "iPad3,2", "iPad3,3",
		"iPad3,4", "iPad3,5", "iPad3,6", "iPad4,1", "iPad4,2", "iPad4,3",
		"iPad5,3", "iPad5,4", "iPad6,7", "iPad6,8", "iPad6,3", "iPad6,4",
		"iPad6,11", "iPad6,12", "iPad7,1", "iPad7,2", "iPad7,3", "iPad7,4",
	},
	protocol.DeviceFireOS: {
		"AMAZON KFARWI", "AMAZON KFAUWI", "AMAZON KFFOWI", "AMAZON KFDOWI", "AMAZON KFONWI", "AMAZON KFMUWI", "AMAZON KFTRWI", "AMAZON KFDONWI", "AMAZON KFMEWI", "AMAZON KFSAWI", "AMAZON KFJWI", "AMAZON KFTBWI", "AMAZON KFGIWI", "AMAZON KFKAWI",
	},
	protocol.DeviceGearVR: {
		"SM-R320", "SM-R321", "SM-R322", "SM-R323", "SM-R324",
	},
	protocol.DeviceOSX: {
		"MacBookPro18,1", "MacBookPro18,2", "MacBookPro18,3", "MacBookPro18,4",
		"MacBookAir10,1",
		"MacBookPro11,1", "MacBookPro11,2", "MacBookPro11,3", "MacBookPro11,4", "MacBookPro11,5",
		"MacBookPro12,1", "MacBookPro13,1", "MacBookPro13,2", "MacBookPro13,3", "MacBookPro14,1",
		"MacBookPro14,2", "MacBookPro14,3", "MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3",
		"MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,3", "MacBookAir5,1", "MacBookAir5,2",
		"MacBookAir6,1", "MacBookAir6,2", "MacBookAir7,1", "MacBookAir7,2", "MacBookAir8,1",
		"MacBookAir8,2", "MacBookAir9,1", "MacBookAir9,2", "Macmini6,1", "Macmini6,2",
	},
	protocol.DeviceWin10: {
		"Surface_Pro_11", "Surface_Laptop_7", "Surface_Laptop_Studio_2", "ROG_Ally",
		"Surface_Pro_3", "Surface_Pro_1796", "Surface_Pro_6", "Surface_Pro_7", "Surface_Pro_7+", "Surface_Pro_8", "Surface_Pro_X", "Surface_Laptop", "Surface_Laptop_2", "Surface_Laptop_3", "Surface_Laptop_4", "Surface_Laptop_Studio", "Surface_Book", "Surface_Book_2", "Surface_Book_3", "Surface_Go", "Surface_Go_2", "Surface_Go_3", "Surface_Studio", "Surface_Studio_2", "Surface_Hub", "Surface_Hub_2S",
		"DELL_XPS_8930", "HP_Pavilion_590", "Lenovo_ThinkCentre_M920", "Acer_Aspire_TC-885", "ASUS_ROG_Strix_G15", "Alienware_Aurora_R11", "CyberPowerPC_Gamer_Xtreme", "MSI_Trident_3", "HP_OMEN_30L", "Corsair_One_i164",
		"HP_Spectre_x360", "Lenovo_Yoga_C940", "Dell_XPS_13", "HP_Envy_13", "Microsoft_Surface_Laptop_4", "Lenovo_ThinkPad_X1_Carbon", "Dell_XPS_15", "HP_Spectre_x360_15", "Microsoft_Surface_Book_3", "Lenovo_Yoga_9i",
		"Microsoft_Surface_Pro_7", "Microsoft_Surface_Pro_7+", "Microsoft_Surface_Pro_8", "Microsoft_Surface_Pro_X", "Microsoft_Surface_Pro_6", "Microsoft_Surface_Pro_5", "Microsoft_Surface_Pro_4", "Microsoft_Surface_Pro_3", "Microsoft_Surface_Pro_2", "Microsoft_Surface_Pro",
		"Acer_Swift_3", "ASUS_ZenBook_13", "Dell_Inspiron_15", "HP_Pavilion_15", "Lenovo_IdeaPad_3", "Acer_Aspire_5", "ASUS_ROG_Strix_G17", "Alienware_m15", "CyberPowerPC_Tracer_III", "MSI_GS66",
		"HP_Spectre_x360_14", "Lenovo_Yoga_7i", "Dell_XPS_17", "HP_Envy_17", "Microsoft_Surface_Laptop_Studio", "Lenovo_ThinkPad_X1_Extreme", "Dell_XPS_15_2-in-1", "HP_Spectre_x360_15_2-in-1", "Microsoft_Surface_Book_2", "Lenovo_Yoga_9i_15",
		"Microsoft_Surface_Laptop_3", "Microsoft_Surface_Laptop_2", "Microsoft_Surface_Laptop", "Microsoft_Surface_Book", "Microsoft_Surface_Book_2", "Microsoft_Surface_Book_3", "Microsoft_Surface_Go", "Microsoft_Surface_Go_2", "Microsoft_Surface_Go_3", "Microsoft_Surface_Studio",
	},
	protocol.DeviceTVOS: {
		"AppleTV5,3", "AppleTV6,2",
	},
	protocol.DeviceOrbis: {
		"CFI-1000A", "CFI-1001A", "CUH-1000A", "CUH-1001A", "CUH-1002A", "CUH-1003A", "CUH-1004A",
	},
	protocol.DeviceNX: {
		"HAC-001", "HAC-001-01", "HAC-001-02",
	},
	protocol.DeviceXBOX: {
		"XboxSeriesX", "XboxSeriesS", "XboxOne", "XboxOneS", "XboxOneX",
	},
	protocol.DeviceLinux: {
		"Linux", "Ubuntu", "Debian", "Fedora", "CentOS",
	},
}
