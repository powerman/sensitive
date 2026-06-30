package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"

	"github.com/shopspring/decimal"
)

// Secret is an interface implemented
// by both plain sensitive types and Ref[T] and Handle[T],
// allowing them to be used interchangeably.
//
//nolint:iface // This is a public API for users of this package.
type Secret[T any] interface {
	ExposeSecret() T
}

var (
	_ fmt.Formatter          = (*Ref[any])(nil)
	_ json.Marshaler         = (*Ref[any])(nil)
	_ encoding.TextMarshaler = (*Ref[any])(nil)
)

// Ref holds a secret value that fmt reflection cannot reach, and behaves
// like []byte for equality: == is a compile-time error, so an accidental
// comparison fails loudly instead of silently returning false.
//
// Use Ref in two cases (see the package doc for the full rule):
//   - the element type's == does not compare by value: []byte, decimals,
//     composite structs. These cannot be a [Handle] element, so they belong
//     here by construction.
//   - the element type's == DOES work by value, but using it is harmful:
//     passwords and hashes are compared constant-time (against another
//     hash), never with ==, so deny == by using Ref[string].
//
// The zero value is safe: [Ref.ExposeSecret] returns the zero T.
//
// == on a Ref, or on any struct containing a Ref field, is a compile-time
// error. Compare values explicitly when needed — [bytes.Equal] for []byte,
// decimal.Decimal.Equal for decimals, a constant-time compare for hashes —
// or compare whole structs in tests with [reflect.DeepEqual], which reads
// through Ref and compares by value.
type Ref[T any] struct {
	_  [0]func()
	pp **T
}

// New returns a [Ref] holding a copy of v.
func New[T any](v T) Ref[T] {
	p := &v
	return Ref[T]{pp: &p}
}

// ExposeSecret returns the stored value,
// or the zero T if the Ref is nil or was created with the zero value.
func (r Ref[T]) ExposeSecret() T {
	if r.pp == nil || *r.pp == nil {
		var z T
		return z
	}
	return **r.pp
}

// Format implements [fmt.Formatter].
func (r Ref[T]) Format(f fmt.State, c rune) {
	switch v := any(r.ExposeSecret()).(type) {
	case bool:
		FormatBoolFn(Bool(v), f, c)
	case []byte:
		FormatBytesFn(Bytes(v), f, c)
	case decimal.Decimal:
		FormatDecimalFn(Decimal(v), f, c)
	case float32:
		FormatFloat32Fn(Float32(v), f, c)
	case float64:
		FormatFloat64Fn(Float64(v), f, c)
	case int:
		FormatIntFn(Int(v), f, c)
	case int8:
		FormatInt8Fn(Int8(v), f, c)
	case int16:
		FormatInt16Fn(Int16(v), f, c)
	case int32:
		FormatInt32Fn(Int32(v), f, c)
	case int64:
		FormatInt64Fn(Int64(v), f, c)
	case string:
		FormatStringFn(String(v), f, c)
	case uint:
		FormatUintFn(Uint(v), f, c)
	case uint8:
		FormatUint8Fn(Uint8(v), f, c)
	case uint16:
		FormatUint16Fn(Uint16(v), f, c)
	case uint32:
		FormatUint32Fn(Uint32(v), f, c)
	case uint64:
		FormatUint64Fn(Uint64(v), f, c)
	default:
		var z T
		Format(f, c, z)
	}
}

// MarshalJSON implements [json.Marshaler].
//
//lint:ignore errchkjson // Delegates to existing marshalers.
func (r Ref[T]) MarshalJSON() ([]byte, error) {
	switch v := any(r.ExposeSecret()).(type) {
	case bool:
		return Bool(v).MarshalJSON()
	case []byte:
		return Bytes(v).MarshalJSON()
	case decimal.Decimal:
		return Decimal(v).MarshalJSON()
	case float32:
		return Float32(v).MarshalJSON()
	case float64:
		return Float64(v).MarshalJSON()
	case int:
		return Int(v).MarshalJSON()
	case int8:
		return Int8(v).MarshalJSON()
	case int16:
		return Int16(v).MarshalJSON()
	case int32:
		return Int32(v).MarshalJSON()
	case int64:
		return Int64(v).MarshalJSON()
	case string:
		return String(v).MarshalJSON()
	case uint:
		return Uint(v).MarshalJSON()
	case uint8:
		return Uint8(v).MarshalJSON()
	case uint16:
		return Uint16(v).MarshalJSON()
	case uint32:
		return Uint32(v).MarshalJSON()
	case uint64:
		return Uint64(v).MarshalJSON()
	default:
		return nil, nil
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (r Ref[T]) MarshalText() (text []byte, err error) {
	switch v := any(r.ExposeSecret()).(type) {
	case bool:
		return Bool(v).MarshalText()
	case []byte:
		return Bytes(v).MarshalText()
	case decimal.Decimal:
		return Decimal(v).MarshalText()
	case float32:
		return Float32(v).MarshalText()
	case float64:
		return Float64(v).MarshalText()
	case int:
		return Int(v).MarshalText()
	case int8:
		return Int8(v).MarshalText()
	case int16:
		return Int16(v).MarshalText()
	case int32:
		return Int32(v).MarshalText()
	case int64:
		return Int64(v).MarshalText()
	case string:
		return String(v).MarshalText()
	case uint:
		return Uint(v).MarshalText()
	case uint8:
		return Uint8(v).MarshalText()
	case uint16:
		return Uint16(v).MarshalText()
	case uint32:
		return Uint32(v).MarshalText()
	case uint64:
		return Uint64(v).MarshalText()
	default:
		return nil, nil
	}
}
