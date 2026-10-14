package protocol

// DeviceOS is a device DeviceOS identifier. It holds a value of one of the constants below and may be found
// in packets such as the Login packet.
type DeviceOS int

// DeviceUnknown is the fallback device/build platform, used when the platform is not any of the known
// values below.
const DeviceUnknown DeviceOS = -1

const (
	DeviceAndroid DeviceOS = iota + 1
	DeviceIOS
	DeviceOSX
	DeviceFireOS
	// Deprecated: DeviceGearVR is deprecated as of 1.21.50.
	DeviceGearVR
	DeviceHololens
	DeviceWin10
	DeviceWin32
	DeviceDedicated
	// Deprecated: DeviceTVOS is deprecated as of 1.20.10.
	DeviceTVOS
	DeviceOrbis // PlayStation
	DeviceNX
	DeviceXBOX
	// Deprecated: DeviceWP is deprecated as of 1.20.10.
	DeviceWP // Windows Phone
	DeviceLinux
)

// Name returns the canonical display name of a device OS, including Unknown for
// DeviceUnknown. Values outside the defined enum return an empty name and false.
func (os DeviceOS) Name() (string, bool) {
	names := deviceOSNames()
	if os == DeviceUnknown {
		return names[0], true
	}
	if os < DeviceAndroid || uint(os) >= uint(len(names)) {
		return "", false
	}
	return names[os], true
}

// ParseDeviceOS resolves a canonical device OS name. Names are case-sensitive;
// unknown names return DeviceUnknown and false.
func ParseDeviceOS(name string) (DeviceOS, bool) {
	for os, candidate := range deviceOSNames() {
		if candidate == name {
			if os == 0 {
				return DeviceUnknown, true
			}
			return DeviceOS(os), true
		}
	}
	return DeviceUnknown, false
}

// deviceOSNames provides one immutable name table for formatting and parsing.
func deviceOSNames() [16]string {
	return [...]string{
		"Unknown", "Android", "iOS", "macOS", "FireOS", "Gear VR", "HoloLens",
		"Windows 10 UWP", "Windows", "Dedicated Server", "tvOS", "PlayStation",
		"Nintendo Switch", "Xbox", "Windows Phone", "Linux",
	}
}
