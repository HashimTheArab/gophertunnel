package protocol

type BuildPlatform int32

const (
	DeviceUnknown   BuildPlatform = -1
	DeviceAndroid   BuildPlatform = 1
	DeviceIOS       BuildPlatform = 2
	DeviceOSX       BuildPlatform = 3
	DeviceFireOS    BuildPlatform = 4
	DeviceGearVR    BuildPlatform = 5
	DeviceWin10     BuildPlatform = 7
	DeviceWin32     BuildPlatform = 8
	DeviceDedicated BuildPlatform = 9
	DeviceTVOS      BuildPlatform = 10
	DeviceOrbis     BuildPlatform = 11
	DeviceNX        BuildPlatform = 12
	DeviceXBOX      BuildPlatform = 13
	DeviceWP        BuildPlatform = 14
	DeviceLinux     BuildPlatform = 15
)

// Marshal reads or writes BuildPlatform through its int32 wire encoding.
func (x *BuildPlatform) Marshal(io IO) { io.Int32((*int32)(x)) }
