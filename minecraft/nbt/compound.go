package nbt

// Compound is a decoded NBT compound. Nested values retain the Go map, list,
// array and scalar shapes produced by the decoder. Clone and Equal operate on
// those shapes without encoding or normalising them.
type Compound map[string]any
