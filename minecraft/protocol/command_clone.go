package protocol

import "slices"

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c Command) Clone() Command {
	out := c
	out.ChainedSubcommandOffsets = slices.Clone(c.ChainedSubcommandOffsets)
	out.Overloads = slices.Clone(c.Overloads)
	for i := range out.Overloads {
		out.Overloads[i] = c.Overloads[i].Clone()
	}
	return out
}

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c CommandOverload) Clone() CommandOverload {
	out := c
	out.Parameters = slices.Clone(c.Parameters)
	return out
}

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c CommandEnum) Clone() CommandEnum {
	out := c
	out.ValueIndices = slices.Clone(c.ValueIndices)
	return out
}

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c ChainedSubcommand) Clone() ChainedSubcommand {
	out := c
	out.Values = slices.Clone(c.Values)
	return out
}

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c DynamicEnum) Clone() DynamicEnum {
	out := c
	out.Values = slices.Clone(c.Values)
	return out
}

// Clone returns an independent structural copy of c, preserving nil slices and
// all values without encoding or normalising them.
func (c CommandEnumConstraint) Clone() CommandEnumConstraint {
	out := c
	out.Constraints = slices.Clone(c.Constraints)
	return out
}
