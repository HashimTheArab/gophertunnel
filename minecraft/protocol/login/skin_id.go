package login

// classicSkinPackID identifies the built-in classic skin pack.
const classicSkinPackID = "c18e65aa-7b21-4637-9b63-8ad63622ef01"

// DefaultSkinID returns the custom model's skin-pack ID for a default skin upload.
// It is independent of the client's authentication and device IDs. Supplied skin
// IDs, including marketplace and persona IDs, should be preserved instead.
func DefaultSkinID(armSize string) string {
	name := "Custom"
	if armSize == "slim" {
		name = "CustomSlim"
	}
	return classicSkinPackID + "." + name
}
