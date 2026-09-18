package protocol

type EduSharedURIResource struct {
	ButtonName string
	LinkURI    string
}

// Marshal reads or writes EduSharedURIResource using its canonical wire layout.
func (x *EduSharedURIResource) Marshal(io IO) {
	io.String(&x.ButtonName)
	io.String(&x.LinkURI)
}

type EducationLevelSettings struct {
	CodeBuilderDefaultURI        string
	CodeBuilderTitle             string
	CanResizeCodeBuilder         bool
	DisableLegacyTitleBar        bool
	PostProcessFilter            string
	ScreenshotBorderResourcePath string
	AgentCapabilities            Optional[bool]
	LocalSettings                EducationLocalLevelSettings
	DeprecatedAlwaysFalse        bool
	ExternalLinkSettings         Optional[ExternalLinkSettings]
}

// Marshal reads or writes EducationLevelSettings using its canonical wire layout.
func (x *EducationLevelSettings) Marshal(io IO) {
	io.String(&x.CodeBuilderDefaultURI)
	io.String(&x.CodeBuilderTitle)
	io.Bool(&x.CanResizeCodeBuilder)
	io.Bool(&x.DisableLegacyTitleBar)
	io.String(&x.PostProcessFilter)
	io.String(&x.ScreenshotBorderResourcePath)
	OptionalFunc(io, &x.AgentCapabilities, io.Bool)
	x.LocalSettings.Marshal(io)
	io.Bool(&x.DeprecatedAlwaysFalse)
	OptionalMarshaler(io, &x.ExternalLinkSettings)
}

type EducationLocalLevelSettings struct {
	CodeBuilderOverrideURI Optional[string]
}

// Marshal reads or writes EducationLocalLevelSettings using its canonical wire layout.
func (x *EducationLocalLevelSettings) Marshal(io IO) {
	OptionalFunc(io, &x.CodeBuilderOverrideURI, io.String)
}

type ExternalLinkSettings struct {
	URL         string
	DisplayName string
}

// Marshal reads or writes ExternalLinkSettings using its canonical wire layout.
func (x *ExternalLinkSettings) Marshal(io IO) {
	io.String(&x.URL)
	io.String(&x.DisplayName)
}
