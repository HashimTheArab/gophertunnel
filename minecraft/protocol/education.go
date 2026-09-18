package protocol

// EducationExternalLinkSettings ...
type EducationExternalLinkSettings struct {
	// URL is the external link URL.
	URL string
	// DisplayName is the display name in game.
	DisplayName string
}

// Marshal reads or writes EducationExternalLinkSettings using its canonical wire layout.
func (x *EducationExternalLinkSettings) Marshal(io IO) {
	io.String(&x.URL)
	io.String(&x.DisplayName)
}

type EducationLocalLevelSettings struct {
	CodeBuilderOverrideURI Optional[string]
}

// Marshal reads or writes EducationLocalLevelSettings using its canonical wire layout.
func (x *EducationLocalLevelSettings) Marshal(io IO) {
	OptionalFunc(io, &x.CodeBuilderOverrideURI, io.String)
}

// EducationSharedResourceURI is an education edition feature that is used for transmitting education resource
// settings to clients. It contains a button name and a link URL.
type EducationSharedResourceURI struct {
	// ButtonName is the button name of the resource URI.
	ButtonName string
	// LinkURI is the link URI for the resource URI.
	LinkURI string
}

// Marshal reads or writes EducationSharedResourceURI using its canonical wire layout.
func (x *EducationSharedResourceURI) Marshal(io IO) {
	io.String(&x.ButtonName)
	io.String(&x.LinkURI)
}
