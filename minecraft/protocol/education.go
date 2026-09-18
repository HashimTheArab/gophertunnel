package protocol

// EduSharedURIResource is an education edition feature that is used for transmitting education resource
// settings to clients. It contains a button name and a link URL.
type EduSharedURIResource struct {
	// ButtonName is the button name of the resource URI.
	ButtonName string
	// LinkURI is the link URI for the resource URI.
	LinkURI string
}

// Marshal reads or writes EduSharedURIResource using its canonical wire layout.
func (x *EduSharedURIResource) Marshal(io IO) {
	io.String(&x.ButtonName)
	io.String(&x.LinkURI)
}

type EducationLocalLevelSettings struct {
	CodeBuilderOverrideURI Optional[string]
}

// Marshal reads or writes EducationLocalLevelSettings using its canonical wire layout.
func (x *EducationLocalLevelSettings) Marshal(io IO) {
	OptionalFunc(io, &x.CodeBuilderOverrideURI, io.String)
}

// ExternalLinkSettings ...
type ExternalLinkSettings struct {
	// URL is the external link URL.
	URL string
	// DisplayName is the display name in game.
	DisplayName string
}

// Marshal reads or writes ExternalLinkSettings using its canonical wire layout.
func (x *ExternalLinkSettings) Marshal(io IO) {
	io.String(&x.URL)
	io.String(&x.DisplayName)
}
