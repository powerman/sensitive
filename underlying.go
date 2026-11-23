package sensitive

import "reflect"

// Named types (e.g. type Token string) are handled by their underlying type:
// the type switches over supported types only know the predeclared types,
// so a named value (or a pointer to it) is converted to its underlying type first.

// underlyingType returns the underlying type of t if it is a supported one,
// i.e. a predeclared type or []byte; otherwise it returns nil.
// A type which is already predeclared yields itself.
func underlyingType(t reflect.Type) reflect.Type {
	switch t.Kind() {
	case reflect.String:
		return reflect.TypeFor[string]()
	case reflect.Bool:
		return reflect.TypeFor[bool]()
	case reflect.Int:
		return reflect.TypeFor[int]()
	case reflect.Int8:
		return reflect.TypeFor[int8]()
	case reflect.Int16:
		return reflect.TypeFor[int16]()
	case reflect.Int32:
		return reflect.TypeFor[int32]()
	case reflect.Int64:
		return reflect.TypeFor[int64]()
	case reflect.Uint:
		return reflect.TypeFor[uint]()
	case reflect.Uint8:
		return reflect.TypeFor[uint8]()
	case reflect.Uint16:
		return reflect.TypeFor[uint16]()
	case reflect.Uint32:
		return reflect.TypeFor[uint32]()
	case reflect.Uint64:
		return reflect.TypeFor[uint64]()
	case reflect.Float32:
		return reflect.TypeFor[float32]()
	case reflect.Float64:
		return reflect.TypeFor[float64]()
	case reflect.Slice:
		if t.Elem() == reflect.TypeFor[byte]() {
			return reflect.TypeFor[[]byte]()
		}
	default:
	}
	return nil
}

// underlying returns v converted to its underlying type,
// so a type switch over the supported types also matches named types.
// Any other value, including a nil interface, is returned as is.
func underlying(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	pt := underlyingType(rv.Type())
	if pt == nil || pt == rv.Type() {
		return v
	}
	return rv.Convert(pt).Interface()
}

// underlyingPtr is [underlying] for a non-nil pointer p:
// the result points to the same value, so the caller can write through it.
func underlyingPtr(p any) any {
	rv := reflect.ValueOf(p)
	pt := underlyingType(rv.Type().Elem())
	if pt == nil || pt == rv.Type().Elem() {
		return p
	}
	return rv.Convert(reflect.PointerTo(pt)).Interface()
}

// nilText is the text output for a type which is not supported by Ref or Handle,
// e.g. a composite struct: it looks nothing like real data, and it never fails an encoder.
const nilText = "<nil>"
