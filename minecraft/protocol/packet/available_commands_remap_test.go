package packet

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// commandTableFixture includes every index-bearing field and nested slice in
// the AvailableCommands schema.
func commandTableFixture() (*AvailableCommands, *AvailableCommands) {
	destination := &AvailableCommands{
		EnumValues:              []string{"old"},
		ChainedSubcommandValues: []string{"old_chain"},
		Suffixes:                []string{"old_suffix"},
		Enums:                   []protocol.CommandEnum{{Type: "Reuse", ValueIndices: []uint32{0}}},
		ChainedSubcommands:      []protocol.ChainedSubcommand{{Name: "old", Values: []protocol.ChainedSubcommandValue{{Index: 0, Value: 0}}}},
		Commands:                []protocol.Command{{Name: "old", AliasesOffset: math.MaxUint32}},
		DynamicEnums:            []protocol.DynamicEnum{{Type: "Old", Values: []string{"old"}}},
		Constraints:             []protocol.CommandEnumConstraint{{EnumIndex: 0, EnumValueIndex: 0, Constraints: []byte{1}}},
	}
	source := &AvailableCommands{
		EnumValues:              []string{"new_a", "new_b"},
		ChainedSubcommandValues: []string{"new_chain"},
		Suffixes:                []string{"new_suffix_a", "new_suffix_b"},
		Enums:                   []protocol.CommandEnum{{Type: "Reuse"}, {Type: "New", ValueIndices: []uint32{0, 1}}},
		ChainedSubcommands:      []protocol.ChainedSubcommand{{Name: "new", Values: []protocol.ChainedSubcommandValue{{Index: 0, Value: 1}}}},
		Commands: []protocol.Command{{
			Name: "new", Description: "new description", Flags: 3, PermissionLevel: protocol.CommandPermissionLevelHost,
			AliasesOffset: 1, ChainedSubcommandOffsets: []uint32{0},
			Overloads: []protocol.CommandOverload{{Chaining: true, Parameters: []protocol.CommandParameter{
				{Name: "enum", Type: protocol.CommandArgValid | protocol.CommandArgEnum | 1},
				{Name: "reuse", Type: protocol.CommandArgValid | protocol.CommandArgEnum},
				{Name: "suffix", Type: protocol.CommandArgValid | protocol.CommandArgSuffixed | 1},
				{Name: "soft", Type: protocol.CommandArgValid | protocol.CommandArgSoftEnum, Optional: true, Options: 3},
				{Name: "basic", Type: protocol.CommandArgValid | protocol.CommandArgTypeInt},
				{Name: "chain", Type: protocol.CommandArgTypeChainedCommand},
			}}},
		}, {Name: "no_alias", AliasesOffset: math.MaxUint32}},
		DynamicEnums: []protocol.DynamicEnum{{Type: "New", Values: []string{"new"}}},
		Constraints:  []protocol.CommandEnumConstraint{{EnumIndex: 1, EnumValueIndex: 1, Constraints: []byte{2, 3}}},
	}
	return destination, source
}

func TestAvailableCommands_AppendCommandTablesRemapsAllReferences(t *testing.T) {
	destination, source := commandTableFixture()
	commands, err := destination.AppendCommandTables(source, map[uint32]uint32{0: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(destination.Commands) != 1 || destination.Commands[0].Name != "old" {
		t.Fatalf("append chose command publication policy: %+v", destination.Commands)
	}
	if !slices.Equal(destination.EnumValues, []string{"old", "new_a", "new_b"}) ||
		!slices.Equal(destination.ChainedSubcommandValues, []string{"old_chain", "new_chain"}) ||
		!slices.Equal(destination.Suffixes, []string{"old_suffix", "new_suffix_a", "new_suffix_b"}) {
		t.Fatalf("string tables were not appended: %+v", destination)
	}
	if len(destination.Enums) != 2 || !slices.Equal(destination.Enums[1].ValueIndices, []uint32{1, 2}) {
		t.Fatalf("enum remapping = %+v", destination.Enums)
	}
	if len(destination.ChainedSubcommands) != 2 || destination.ChainedSubcommands[1].Values[0].Index != 1 || destination.ChainedSubcommands[1].Values[0].Value != 1 {
		t.Fatalf("chained subcommand remapping = %+v", destination.ChainedSubcommands)
	}
	if commands[0].AliasesOffset != 1 || !slices.Equal(commands[0].ChainedSubcommandOffsets, []uint32{1}) || commands[1].AliasesOffset != math.MaxUint32 {
		t.Fatalf("command remapping = %+v", commands)
	}
	wantTypes := []uint32{
		protocol.CommandArgValid | protocol.CommandArgEnum | 1,
		protocol.CommandArgValid | protocol.CommandArgEnum,
		protocol.CommandArgValid | protocol.CommandArgSuffixed | 2,
		protocol.CommandArgValid | protocol.CommandArgSoftEnum | 1,
		protocol.CommandArgValid | protocol.CommandArgTypeInt,
		protocol.CommandArgTypeChainedCommand,
	}
	for i, parameter := range commands[0].Overloads[0].Parameters {
		if parameter.Type != wantTypes[i] {
			t.Errorf("parameter %d type = %#x, want %#x", i, parameter.Type, wantTypes[i])
		}
	}
	if !reflect.DeepEqual(destination.DynamicEnums[1], source.DynamicEnums[0]) {
		t.Fatalf("dynamic enum lost values: %+v", destination.DynamicEnums)
	}
	constraint := destination.Constraints[1]
	if constraint.EnumIndex != 1 || constraint.EnumValueIndex != 2 || !slices.Equal(constraint.Constraints, []byte{2, 3}) {
		t.Fatalf("constraint remapping = %+v", constraint)
	}
	if commands[0].Description != source.Commands[0].Description || commands[0].Flags != source.Commands[0].Flags || commands[0].PermissionLevel != source.Commands[0].PermissionLevel ||
		!commands[0].Overloads[0].Chaining || !commands[0].Overloads[0].Parameters[3].Optional || commands[0].Overloads[0].Parameters[3].Options != 3 {
		t.Fatalf("non-reference command values changed: %+v", commands)
	}
}

func TestAvailableCommands_AppendCommandTablesRejectsInvalidReferencesAtomically(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*AvailableCommands)
		reuse map[uint32]uint32
	}{
		{name: "enum value", edit: func(p *AvailableCommands) { p.Enums[1].ValueIndices[0] = 2 }},
		{name: "reused enum value", edit: func(p *AvailableCommands) { p.Enums[0].ValueIndices = []uint32{2} }, reuse: map[uint32]uint32{0: 0}},
		{name: "aliases", edit: func(p *AvailableCommands) { p.Commands[0].AliasesOffset = 2 }},
		{name: "enum parameter", edit: func(p *AvailableCommands) {
			p.Commands[0].Overloads[0].Parameters[0].Type = protocol.CommandArgValid | protocol.CommandArgEnum | 2
		}},
		{name: "suffix parameter", edit: func(p *AvailableCommands) {
			p.Commands[0].Overloads[0].Parameters[0].Type = protocol.CommandArgValid | protocol.CommandArgSuffixed | 2
		}},
		{name: "dynamic parameter", edit: func(p *AvailableCommands) {
			p.Commands[0].Overloads[0].Parameters[0].Type = protocol.CommandArgValid | protocol.CommandArgSoftEnum | 1
		}},
		{name: "unknown flags", edit: func(p *AvailableCommands) { p.Commands[0].Overloads[0].Parameters[0].Type |= 0x80000000 }},
		{name: "missing valid flag", edit: func(p *AvailableCommands) { p.Commands[0].Overloads[0].Parameters[0].Type &^= protocol.CommandArgValid }},
		{name: "ambiguous table flags", edit: func(p *AvailableCommands) {
			p.Commands[0].Overloads[0].Parameters[0].Type |= protocol.CommandArgSoftEnum
		}},
		{name: "chained table flags", edit: func(p *AvailableCommands) {
			p.Commands[0].Overloads[0].Parameters[0].Type |= protocol.CommandArgTypeChainedCommand
		}},
		{name: "chained value", edit: func(p *AvailableCommands) { p.ChainedSubcommands[0].Values[0].Index = 1 }},
		{name: "chained enum", edit: func(p *AvailableCommands) { p.ChainedSubcommands[0].Values[0].Value = 2 }},
		{name: "chained offset", edit: func(p *AvailableCommands) { p.Commands[0].ChainedSubcommandOffsets[0] = 1 }},
		{name: "constraint enum", edit: func(p *AvailableCommands) { p.Constraints[0].EnumIndex = 2 }},
		{name: "constraint enum value", edit: func(p *AvailableCommands) { p.Constraints[0].EnumValueIndex = 2 }},
		{name: "reuse source", reuse: map[uint32]uint32{2: 0}},
		{name: "reuse destination", reuse: map[uint32]uint32{0: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination, source := commandTableFixture()
			if test.edit != nil {
				test.edit(source)
			}
			beforeDestination, beforeSource := destination.Clone(), source.Clone()
			if _, err := destination.AppendCommandTables(source, test.reuse); err == nil {
				t.Fatal("invalid reference was accepted")
			}
			if !reflect.DeepEqual(destination, beforeDestination) || !reflect.DeepEqual(source, beforeSource) {
				t.Fatal("validation error mutated a packet")
			}
		})
	}
}

func TestAvailableCommands_AppendPreservesSuffixFlags(t *testing.T) {
	for _, valid := range []uint32{0, protocol.CommandArgValid} {
		destination := &AvailableCommands{Suffixes: []string{"old"}}
		source := &AvailableCommands{
			Suffixes: []string{"ticks"},
			Commands: []protocol.Command{{
				Name: "delay", AliasesOffset: math.MaxUint32,
				Overloads: []protocol.CommandOverload{{Parameters: []protocol.CommandParameter{{
					Name: "duration", Type: protocol.CommandArgSuffixed | valid,
				}}}},
			}},
		}
		before := source.Clone()
		commands, err := destination.AppendCommandTables(source, nil)
		if err != nil {
			t.Fatalf("valid flag %#x: %v", valid, err)
		}
		if got, want := commands[0].Overloads[0].Parameters[0].Type, uint32(protocol.CommandArgSuffixed)|valid|1; got != want {
			t.Fatalf("suffix type = %#x, want %#x", got, want)
		}
		if !reflect.DeepEqual(source, before) || !slices.Equal(destination.Suffixes, []string{"old", "ticks"}) {
			t.Fatal("suffix append changed source or lost suffix values")
		}
	}
}

func TestAvailableCommands_AppendRemapsChainedEnumReferences(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		destination := &AvailableCommands{
			Enums:                   []protocol.CommandEnum{{Type: "Old"}, {Type: "Shared"}},
			ChainedSubcommandValues: []string{"old"},
		}
		source := &AvailableCommands{
			Enums:                   []protocol.CommandEnum{{Type: "Shared"}},
			ChainedSubcommandValues: []string{"new"},
			ChainedSubcommands:      []protocol.ChainedSubcommand{{Name: "execute", Values: []protocol.ChainedSubcommandValue{{Index: 0, Value: 0}}}},
		}
		before := source.Clone()
		var mapping map[uint32]uint32
		wantEnum := uint32(2)
		if reuse {
			mapping, wantEnum = map[uint32]uint32{0: 1}, 1
		}
		if _, err := destination.AppendCommandTables(source, mapping); err != nil {
			t.Fatal(err)
		}
		if got := destination.ChainedSubcommands[0].Values[0]; got.Index != 1 || got.Value != wantEnum {
			t.Fatalf("reuse=%t relationship=%+v, want value=1 enum=%d", reuse, got, wantEnum)
		}
		if !reflect.DeepEqual(source, before) {
			t.Fatal("chained remapping changed source")
		}
	}
}

func TestAvailableCommands_CloneAndAppendDoNotAliasSource(t *testing.T) {
	for _, operation := range []string{"clone", "append"} {
		t.Run(operation, func(t *testing.T) {
			destination, source := commandTableFixture()
			before := source.Clone()
			if operation == "clone" {
				destination = source.Clone()
			} else {
				commands, err := destination.AppendCommandTables(source, nil)
				if err != nil {
					t.Fatal(err)
				}
				destination.Commands = commands
			}
			mutateCommandSlices(reflect.ValueOf(destination).Elem())
			if !reflect.DeepEqual(source, before) {
				t.Fatal("changing detached containers mutated the source")
			}
		})
	}
	if (*AvailableCommands)(nil).Clone() != nil {
		t.Fatal("nil packet clone is non-nil")
	}
	if !reflect.DeepEqual((&AvailableCommands{}).Clone(), &AvailableCommands{}) {
		t.Fatal("clone changed nil slices")
	}
}

// mutateCommandSlices changes every non-empty slice element recursively so a
// newly added mutable schema member cannot silently escape the detachment test.
func mutateCommandSlices(value reflect.Value) {
	switch value.Kind() {
	case reflect.Struct:
		for i := range value.NumField() {
			mutateCommandSlices(value.Field(i))
		}
	case reflect.Slice:
		for i := range value.Len() {
			element := value.Index(i)
			switch element.Kind() {
			case reflect.String:
				element.SetString("changed")
			case reflect.Uint8, reflect.Uint32:
				element.SetUint(element.Uint() + 1)
			default:
				mutateCommandSlices(element)
			}
		}
	case reflect.String:
		value.SetString("changed")
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		value.SetUint(value.Uint() + 1)
	case reflect.Bool:
		value.SetBool(!value.Bool())
	}
}

func TestAvailableCommands_AppendNilAndSelf(t *testing.T) {
	destination, _ := commandTableFixture()
	before := destination.Clone()
	if commands, err := destination.AppendCommandTables(nil, nil); err != nil || commands != nil || !reflect.DeepEqual(destination, before) {
		t.Fatal("nil append changed destination")
	}
	commands, err := destination.AppendCommandTables(destination, nil)
	if err != nil || len(commands) != 1 || len(destination.Enums) != 2 || destination.Enums[1].ValueIndices[0] != 1 {
		t.Fatalf("self append failed: commands=%+v destination=%+v err=%v", commands, destination, err)
	}
	if _, err := (*AvailableCommands)(nil).AppendCommandTables(before, nil); err == nil {
		t.Fatal("nil destination was accepted")
	}
}

func TestAvailableCommands_AppendWithSharedSpareCapacityPreservesSource(t *testing.T) {
	_, source := commandTableFixture()
	before := source.Clone()
	// The first source enum is reused. Without detaching destination's spare
	// capacity, appending the second enum would overwrite its source definition.
	destination := &AvailableCommands{Enums: source.Enums[:1]}
	if _, err := destination.AppendCommandTables(source, map[uint32]uint32{0: 0}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source, before) {
		t.Fatal("append wrote into capacity shared with source")
	}
}

func TestAvailableCommands_CombinedIndexFitsEncoding(t *testing.T) {
	if _, err := appendCommandIndex(1, 2, int(protocol.CommandArgIndexMask), protocol.CommandArgIndexMask); err == nil {
		t.Fatal("packed argument index overflow was accepted")
	}
	if _, err := appendCommandIndex(1, 2, math.MaxUint32, math.MaxUint32); err == nil {
		t.Fatal("uint32 table index overflow was accepted")
	}
}

func TestAvailableCommands_RemapSchemaExhaustive(t *testing.T) {
	// Every member must be reviewed when the schema changes, including scalar
	// flags that might introduce a new interpretation of a table reference.
	schemas := map[reflect.Type][]string{
		reflect.TypeFor[AvailableCommands]():               {"EnumValues", "ChainedSubcommandValues", "Suffixes", "Enums", "ChainedSubcommands", "Commands", "DynamicEnums", "Constraints"},
		reflect.TypeFor[protocol.Command]():                {"Name", "Description", "Flags", "PermissionLevel", "AliasesOffset", "ChainedSubcommandOffsets", "Overloads"},
		reflect.TypeFor[protocol.CommandEnum]():            {"Type", "ValueIndices"},
		reflect.TypeFor[protocol.CommandOverload]():        {"Chaining", "Parameters"},
		reflect.TypeFor[protocol.CommandParameter]():       {"Name", "Type", "Optional", "Options"},
		reflect.TypeFor[protocol.ChainedSubcommand]():      {"Name", "Values"},
		reflect.TypeFor[protocol.ChainedSubcommandValue](): {"Index", "Value"},
		reflect.TypeFor[protocol.DynamicEnum]():            {"Type", "Values"},
		reflect.TypeFor[protocol.CommandEnumConstraint]():  {"EnumValueIndex", "EnumIndex", "Constraints"},
	}
	for typ, names := range schemas {
		var fields []string
		for field := range typ.Fields() {
			fields = append(fields, field.Name)
		}
		if !slices.Equal(fields, names) {
			t.Errorf("%v schema changed: review Clone/AppendCommandTables for %v (was %v)", typ, fields, names)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "../command.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var flags []string
	for _, declaration := range file.Decls {
		constants, ok := declaration.(*ast.GenDecl)
		if !ok || constants.Tok != token.CONST {
			continue
		}
		for _, specification := range constants.Specs {
			for _, name := range specification.(*ast.ValueSpec).Names {
				if strings.HasPrefix(name.Name, "CommandArg") && !strings.HasPrefix(name.Name, "CommandArgType") && name.Name != "CommandArgIndexMask" {
					flags = append(flags, name.Name)
				}
			}
		}
	}
	if !slices.Equal(flags, []string{"CommandArgValid", "CommandArgEnum", "CommandArgSuffixed", "CommandArgSoftEnum"}) {
		t.Errorf("command argument flags changed: review remapCommandArgument for %v", flags)
	}
}
