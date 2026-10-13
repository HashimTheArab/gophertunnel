package protocol

import (
	"reflect"
	"testing"
)

func TestCommandClone_PreservesValuesAndDetachesSlices(t *testing.T) {
	tests := []struct {
		name    string
		fixture func() any
		clone   func(any) any
	}{
		{
			name: "command",
			fixture: func() any {
				return Command{
					Name: "Example", Description: "description", Flags: 0xffff, PermissionLevel: 0xff,
					AliasesOffset: 0xffffffff, ChainedSubcommandOffsets: []uint32{0xffffffff, 1},
					Overloads: []CommandOverload{
						{Chaining: true, Parameters: []CommandParameter{{Name: "argument", Type: 0xffffffff, Optional: true, Options: 0xff}}},
						{},
						{Parameters: make([]CommandParameter, 0, 1)},
					},
				}
			},
			clone: func(value any) any { return value.(Command).Clone() },
		},
		{
			name: "overload",
			fixture: func() any {
				return CommandOverload{Chaining: true, Parameters: []CommandParameter{
					{Name: "argument", Type: 0xffffffff, Optional: true, Options: 0xff},
				}}
			},
			clone: func(value any) any { return value.(CommandOverload).Clone() },
		},
		{
			name:    "enum",
			fixture: func() any { return CommandEnum{Type: "Enum", ValueIndices: []uint32{0xffffffff, 1}} },
			clone:   func(value any) any { return value.(CommandEnum).Clone() },
		},
		{
			name: "chained subcommand",
			fixture: func() any {
				return ChainedSubcommand{Name: "subcommand", Values: []ChainedSubcommandValue{{Index: 0xffffffff, Value: 0xffffffff}}}
			},
			clone: func(value any) any { return value.(ChainedSubcommand).Clone() },
		},
		{
			name:    "dynamic enum",
			fixture: func() any { return DynamicEnum{Type: "Dynamic", Values: []string{"one", "two"}} },
			clone:   func(value any) any { return value.(DynamicEnum).Clone() },
		},
		{
			name: "constraint",
			fixture: func() any {
				return CommandEnumConstraint{EnumValueIndex: 0xffffffff, EnumIndex: 0xffffffff, Constraints: []byte{0xff, 1}}
			},
			clone: func(value any) any { return value.(CommandEnumConstraint).Clone() },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Discover owned references rather than keeping a separate field list.
			// Adding a reference to a value-only member also fails this check.
			checkCommandCloneFixture(t, reflect.ValueOf(test.fixture()))
			for _, shape := range []string{"nil", "empty", "populated"} {
				t.Run(shape, func(t *testing.T) {
					for _, direction := range []string{"clone", "source"} {
						t.Run(direction, func(t *testing.T) {
							source := commandCloneFixtureShape(test.fixture(), shape)
							want := commandCloneFixtureShape(test.fixture(), shape)
							clone := commandCloneValue(test.clone(source.Interface()))
							if !reflect.DeepEqual(source.Interface(), clone.Interface()) {
								t.Fatal("clone changed values or nil/empty slice shape")
							}
							if direction == "clone" {
								mutateCommandCloneValue(clone)
								checkCommandCloneUnchanged(t, source, want)
							} else {
								mutateCommandCloneValue(source)
								if !reflect.DeepEqual(clone.Interface(), want.Interface()) {
									t.Fatal("source mutation changed the clone")
								}
							}
						})
					}
				})
			}
		})
	}
}

// commandCloneValue makes a value addressable so tests can mutate its slice fields.
func commandCloneValue(value any) reflect.Value {
	out := reflect.New(reflect.TypeOf(value)).Elem()
	out.Set(reflect.ValueOf(value))
	return out
}

// commandCloneFixtureShape creates nil, non-nil empty, or populated slice fixtures.
func commandCloneFixtureShape(value any, shape string) reflect.Value {
	out := commandCloneValue(value)
	if shape == "populated" {
		return out
	}
	for field := range out.Type().Fields() {
		member := out.FieldByIndex(field.Index)
		if member.Kind() != reflect.Slice {
			continue
		}
		if shape == "nil" {
			member.SetZero()
		} else {
			member.Set(reflect.MakeSlice(member.Type(), 0, 1))
		}
	}
	return out
}

// mutateCommandCloneValue edits owned elements and appends to empty slices.
func mutateCommandCloneValue(value reflect.Value) {
	switch value.Kind() {
	case reflect.Struct:
		for i := range value.NumField() {
			mutateCommandCloneValue(value.Field(i))
		}
	case reflect.Slice:
		if value.IsNil() {
			return
		}
		if value.Len() == 0 {
			value.Set(reflect.Append(value, reflect.New(value.Type().Elem()).Elem()))
		}
		for i := range value.Len() {
			mutateCommandCloneValue(value.Index(i))
		}
	case reflect.String:
		value.SetString("changed")
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		value.SetUint(value.Uint() ^ 1)
	case reflect.Bool:
		value.SetBool(!value.Bool())
	}
}

// checkCommandCloneUnchanged includes spare capacity to catch empty-slice append aliases.
func checkCommandCloneUnchanged(t *testing.T, source, want reflect.Value) {
	t.Helper()
	if !reflect.DeepEqual(source.Interface(), want.Interface()) {
		t.Fatal("clone mutation changed the source")
	}
	switch source.Kind() {
	case reflect.Struct:
		for i := range source.NumField() {
			checkCommandCloneUnchanged(t, source.Field(i), want.Field(i))
		}
	case reflect.Slice:
		if !reflect.DeepEqual(source.Slice(0, source.Cap()).Interface(), want.Slice(0, want.Cap()).Interface()) {
			t.Fatal("clone append changed the source's spare capacity")
		}
		for i := range source.Len() {
			checkCommandCloneUnchanged(t, source.Index(i), want.Index(i))
		}
	}
}

// checkCommandCloneFixture requires every owning slice to have a populated fixture,
// and rejects reference kinds not covered by the slice ownership contract.
func checkCommandCloneFixture(t *testing.T, value reflect.Value) {
	t.Helper()
	switch value.Kind() {
	case reflect.Struct:
		for field := range value.Type().Fields() {
			member := value.FieldByIndex(field.Index)
			if member.Kind() == reflect.Slice && member.Len() == 0 {
				t.Fatalf("%v.%s needs a populated ownership fixture", value.Type(), field.Name)
			}
			checkCommandCloneFixture(t, member)
		}
	case reflect.Slice:
		// The first element covers the element schema. Later elements may
		// deliberately exercise nested nil and non-nil empty slice shapes.
		if value.Len() != 0 {
			checkCommandCloneFixture(t, value.Index(0))
		}
	case reflect.String, reflect.Bool, reflect.Uint8, reflect.Uint16, reflect.Uint32:
	default:
		t.Fatalf("%v needs an explicit clone ownership policy", value.Type())
	}
}
