package login

import (
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SchemaDifference describes a field's JSON shape, never its value. An empty Expected
// means the field is not modelled. Array element paths use [] instead of an index.
type SchemaDifference struct {
	Path     string
	Expected string
	Actual   string
}

// SchemaReport is an unverified observation of the incoming client-data JWT. It is
// diagnostic only: clients can forge every field, including the reported version.
// Missing claims are not differences because claim presence varies by client.
type SchemaReport struct {
	ClientProtocol int32
	GameVersion    string
	Differences    []SchemaDifference
	// DecodeFailure identifies a failed parsing stage without retaining the error or payload.
	DecodeFailure string
	// Truncated means inspection hit its work or difference limit.
	Truncated bool
}

var schemaVersion = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}(\.[0-9]{1,5})?$`)

// InspectClientData compares an incoming login request to ClientData's Go fields,
// including nested structs. It does not authenticate, mutate, or reject the request.
// Reports contain at most 32 differences and inspection visits at most 16384 nodes.
func InspectClientData(request []byte) SchemaReport {
	report := SchemaReport{}
	req, err := parseLoginRequest(request)
	if err != nil {
		report.DecodeFailure = "login_envelope"
		return report
	}
	token, err := jwt.ParseSigned(req.RawToken, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		report.DecodeFailure = "client_data_jwt"
		return report
	}
	var raw json.RawMessage
	if err := token.UnsafeClaimsWithoutVerification(&raw); err != nil {
		report.DecodeFailure = "client_data_json"
		return report
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		report.DecodeFailure = "client_data_json"
		return report
	}
	if object, ok := value.(map[string]any); ok {
		if version, ok := object["GameVersion"].(string); ok && schemaVersion.MatchString(version) {
			report.GameVersion = version
		}
	}
	remaining := 16384
	report.compare(value, reflect.TypeFor[ClientData](), "ClientData", &remaining)
	return report
}

// compare walks the declared JSON fields with a bounded work budget.
func (r *SchemaReport) compare(value any, typ reflect.Type, path string, remaining *int) {
	if *remaining == 0 {
		r.Truncated = true
		return
	}
	*remaining--
	for typ.Kind() == reflect.Pointer {
		if value == nil {
			return
		}
		typ = typ.Elem()
	}
	// encoding/json accepts null for every Go field without changing scalar values.
	if value == nil {
		return
	}
	expected := schemaType(typ)
	actual := jsonType(value)
	if expected != actual {
		r.addDifference(SchemaDifference{path, expected, actual})
		return
	}
	if number, ok := value.(json.Number); ok {
		var err error
		switch typ.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			_, err = strconv.ParseInt(string(number), 10, typ.Bits())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			_, err = strconv.ParseUint(string(number), 10, typ.Bits())
		case reflect.Float32, reflect.Float64:
			_, err = strconv.ParseFloat(string(number), typ.Bits())
		}
		if err != nil {
			r.addDifference(SchemaDifference{path, typ.String(), "incompatible number"})
		}
	}
	switch typ.Kind() {
	case reflect.Struct:
		fields := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if !field.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		object := value.(map[string]any)
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if *remaining == 0 {
				r.Truncated = true
				return
			}
			field, ok := fields[key]
			if !ok {
				// Match encoding/json's case-insensitive fallback for known field names.
				for name, candidate := range fields {
					if strings.EqualFold(key, name) {
						field, ok = candidate, true
						break
					}
				}
			}
			if ok {
				r.compare(object[key], field, path+"."+key, remaining)
			} else {
				*remaining--
				r.addDifference(SchemaDifference{path + "." + key, "", jsonType(object[key])})
			}
		}
	case reflect.Slice, reflect.Array:
		for _, item := range value.([]any) {
			if *remaining == 0 {
				r.Truncated = true
				return
			}
			r.compare(item, typ.Elem(), path+"[]", remaining)
		}
	}
}

// addDifference deduplicates array shapes and bounds attacker-controlled field paths.
func (r *SchemaReport) addDifference(d SchemaDifference) {
	if len(d.Path) > 160 {
		d.Path = d.Path[:160]
		r.Truncated = true
	}
	if slices.Contains(r.Differences, d) {
		return
	}
	if len(r.Differences) == 32 {
		r.Truncated = true
		return
	}
	r.Differences = append(r.Differences, d)
}

// schemaType maps the underlying Go kind to its JSON shape.
func schemaType(typ reflect.Type) string {
	switch typ.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Struct, reflect.Map:
		return "object"
	default:
		return "unknown"
	}
}

// jsonType classifies decoded JSON without exposing its contents.
func jsonType(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}
