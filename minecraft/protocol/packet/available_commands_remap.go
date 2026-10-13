package packet

import (
	"fmt"
	"math"
	"slices"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// maxChainedSubcommands is the documented AvailableCommands table limit.
const maxChainedSubcommands = 16

// Clone returns an independent structural copy of pk, preserving nil slices
// and all values without encoding or normalising them. A nil packet stays nil.
func (pk *AvailableCommands) Clone() *AvailableCommands {
	if pk == nil {
		return nil
	}
	out := *pk
	out.EnumValues = slices.Clone(pk.EnumValues)
	out.ChainedSubcommandValues = slices.Clone(pk.ChainedSubcommandValues)
	out.Suffixes = slices.Clone(pk.Suffixes)
	out.Enums = slices.Clone(pk.Enums)
	for i := range out.Enums {
		out.Enums[i].ValueIndices = slices.Clone(pk.Enums[i].ValueIndices)
	}
	out.ChainedSubcommands = slices.Clone(pk.ChainedSubcommands)
	for i := range out.ChainedSubcommands {
		out.ChainedSubcommands[i].Values = slices.Clone(pk.ChainedSubcommands[i].Values)
	}
	out.Commands = slices.Clone(pk.Commands)
	for i := range out.Commands {
		out.Commands[i].ChainedSubcommandOffsets = slices.Clone(pk.Commands[i].ChainedSubcommandOffsets)
		out.Commands[i].Overloads = slices.Clone(pk.Commands[i].Overloads)
		for j := range out.Commands[i].Overloads {
			out.Commands[i].Overloads[j].Parameters = slices.Clone(pk.Commands[i].Overloads[j].Parameters)
		}
	}
	out.DynamicEnums = slices.Clone(pk.DynamicEnums)
	for i := range out.DynamicEnums {
		out.DynamicEnums[i].Values = slices.Clone(pk.DynamicEnums[i].Values)
	}
	out.Constraints = slices.Clone(pk.Constraints)
	for i := range out.Constraints {
		out.Constraints[i].Constraints = slices.Clone(pk.Constraints[i].Constraints)
	}
	return &out
}

// AppendCommandTables appends source's tables and constraints to pk and returns
// independently owned commands whose references point into the combined tables.
// It does not append the commands themselves or choose command replacement or
// visibility policy. reuseEnums explicitly maps source enum indices to existing
// destination enum indices; those source enum definitions are not appended.
//
// Every source reference is validated, including references in reused enum
// definitions. Unknown argument flags, ambiguous table references and indices
// that cannot fit their encoding return an error. On error neither packet is
// changed. On success no appended table or returned command aliases source.
// A nil source is a no-op. Source may also be pk itself.
func (pk *AvailableCommands) AppendCommandTables(source *AvailableCommands, reuseEnums map[uint32]uint32) ([]protocol.Command, error) {
	if source == nil {
		return nil, nil
	}
	if pk == nil {
		return nil, fmt.Errorf("append command tables: nil destination")
	}
	if len(pk.ChainedSubcommands) > maxChainedSubcommands ||
		len(source.ChainedSubcommands) > maxChainedSubcommands-len(pk.ChainedSubcommands) {
		return nil, fmt.Errorf("combined chained subcommands exceed %d definitions", maxChainedSubcommands)
	}
	for from, to := range reuseEnums {
		if uint64(from) >= uint64(len(source.Enums)) || uint64(to) >= uint64(len(pk.Enums)) {
			return nil, fmt.Errorf("reuse enum %d as %d: index out of range", from, to)
		}
	}
	fragment := source.Clone()
	enumIndices := make([]uint32, len(fragment.Enums))
	appendedEnums := fragment.Enums[:0]
	for i, enum := range fragment.Enums {
		for j, index := range enum.ValueIndices {
			mapped, err := appendCommandIndex(index, len(source.EnumValues), len(pk.EnumValues), math.MaxUint32)
			if err != nil {
				return nil, fmt.Errorf("enum %d value %d: %w", i, j, err)
			}
			enum.ValueIndices[j] = mapped
		}
		if existing, ok := reuseEnums[uint32(i)]; ok {
			enumIndices[i] = existing
			continue
		}
		index := uint64(len(pk.Enums)) + uint64(len(appendedEnums))
		if index > math.MaxUint32 {
			return nil, fmt.Errorf("enum %d: combined index overflows uint32", i)
		}
		enumIndices[i] = uint32(index)
		appendedEnums = append(appendedEnums, enum)
	}
	fragment.Enums = appendedEnums
	for i := range fragment.ChainedSubcommands {
		for j := range fragment.ChainedSubcommands[i].Values {
			value := &fragment.ChainedSubcommands[i].Values[j]
			mapped, err := appendCommandIndex(value.Index, len(source.ChainedSubcommandValues), len(pk.ChainedSubcommandValues), math.MaxUint32)
			if err != nil {
				return nil, fmt.Errorf("chained subcommand %d value %d: %w", i, j, err)
			}
			value.Index = mapped
			enum, err := mappedCommandEnum(value.Value, enumIndices)
			if err != nil {
				return nil, fmt.Errorf("chained subcommand %d enum %d: %w", i, j, err)
			}
			value.Value = enum
		}
	}
	for i := range fragment.Commands {
		command := &fragment.Commands[i]
		if command.AliasesOffset != math.MaxUint32 {
			mapped, err := mappedCommandEnum(command.AliasesOffset, enumIndices)
			if err != nil {
				return nil, fmt.Errorf("command %d aliases: %w", i, err)
			}
			command.AliasesOffset = mapped
		}
		for j, index := range command.ChainedSubcommandOffsets {
			mapped, err := appendCommandIndex(index, len(source.ChainedSubcommands), len(pk.ChainedSubcommands), math.MaxUint32)
			if err != nil {
				return nil, fmt.Errorf("command %d chained subcommand %d: %w", i, j, err)
			}
			command.ChainedSubcommandOffsets[j] = mapped
		}
		for j := range command.Overloads {
			for k := range command.Overloads[j].Parameters {
				parameter := &command.Overloads[j].Parameters[k]
				mapped, err := remapCommandArgument(parameter.Type, enumIndices, source, pk)
				if err != nil {
					return nil, fmt.Errorf("command %d overload %d parameter %d: %w", i, j, k, err)
				}
				parameter.Type = mapped
			}
		}
	}
	for i := range fragment.Constraints {
		constraint := &fragment.Constraints[i]
		value, err := appendCommandIndex(constraint.EnumValueIndex, len(source.EnumValues), len(pk.EnumValues), math.MaxUint32)
		if err != nil {
			return nil, fmt.Errorf("constraint %d enum value: %w", i, err)
		}
		enum, err := mappedCommandEnum(constraint.EnumIndex, enumIndices)
		if err != nil {
			return nil, fmt.Errorf("constraint %d enum: %w", i, err)
		}
		constraint.EnumValueIndex, constraint.EnumIndex = value, enum
	}
	// Clipping prevents append from writing into spare capacity shared with
	// source, even when callers constructed the packets from common slices.
	pk.EnumValues = append(slices.Clip(pk.EnumValues), fragment.EnumValues...)
	pk.ChainedSubcommandValues = append(slices.Clip(pk.ChainedSubcommandValues), fragment.ChainedSubcommandValues...)
	pk.Suffixes = append(slices.Clip(pk.Suffixes), fragment.Suffixes...)
	pk.Enums = append(slices.Clip(pk.Enums), fragment.Enums...)
	pk.ChainedSubcommands = append(slices.Clip(pk.ChainedSubcommands), fragment.ChainedSubcommands...)
	pk.DynamicEnums = append(slices.Clip(pk.DynamicEnums), fragment.DynamicEnums...)
	pk.Constraints = append(slices.Clip(pk.Constraints), fragment.Constraints...)
	return fragment.Commands, nil
}

// appendCommandIndex validates a source reference and rebases it into a table.
func appendCommandIndex(index uint32, sourceLength, offset int, maximum uint32) (uint32, error) {
	if uint64(index) >= uint64(sourceLength) {
		return 0, fmt.Errorf("index %d out of range for table of length %d", index, sourceLength)
	}
	mapped := uint64(offset) + uint64(index)
	if mapped > uint64(maximum) {
		return 0, fmt.Errorf("combined index %d exceeds %d", mapped, maximum)
	}
	return uint32(mapped), nil
}

// mappedCommandEnum looks up a source enum in the explicit remapping.
func mappedCommandEnum(index uint32, indices []uint32) (uint32, error) {
	if uint64(index) >= uint64(len(indices)) {
		return 0, fmt.Errorf("enum index %d out of range for table of length %d", index, len(indices))
	}
	return indices[index], nil
}

// remapCommandArgument preserves the argument flags while rebasing its index.
func remapCommandArgument(value uint32, enums []uint32, source, destination *AvailableCommands) (uint32, error) {
	const tableFlags = protocol.CommandArgEnum | protocol.CommandArgSuffixed | protocol.CommandArgSoftEnum
	const knownFlags = protocol.CommandArgValid | tableFlags | protocol.CommandArgTypeChainedCommand
	if value&^uint32(protocol.CommandArgIndexMask|knownFlags) != 0 {
		return 0, fmt.Errorf("unknown argument flags in %#x", value)
	}
	flags := value & tableFlags
	if flags == 0 {
		return value, nil
	}
	if flags&(flags-1) != 0 || value&protocol.CommandArgTypeChainedCommand != 0 ||
		(flags != protocol.CommandArgSuffixed && value&protocol.CommandArgValid == 0) {
		return 0, fmt.Errorf("invalid table argument flags in %#x", value)
	}
	index := value & protocol.CommandArgIndexMask
	var mapped uint32
	var err error
	switch flags {
	case protocol.CommandArgEnum:
		mapped, err = mappedCommandEnum(index, enums)
	case protocol.CommandArgSuffixed:
		mapped, err = appendCommandIndex(index, len(source.Suffixes), len(destination.Suffixes), protocol.CommandArgIndexMask)
	case protocol.CommandArgSoftEnum:
		mapped, err = appendCommandIndex(index, len(source.DynamicEnums), len(destination.DynamicEnums), protocol.CommandArgIndexMask)
	}
	if err != nil {
		return 0, err
	}
	if mapped > protocol.CommandArgIndexMask {
		return 0, fmt.Errorf("combined enum index %d exceeds %d", mapped, protocol.CommandArgIndexMask)
	}
	return value&^uint32(protocol.CommandArgIndexMask) | mapped, nil
}
