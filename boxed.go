package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"

	"github.com/shopspring/decimal"
)

// Secret is an interface implemented
// by both plain sensitive types and Boxed[T],
// allowing them to be used interchangeably.
//
//nolint:iface // This is a public API for users of this package.
type Secret[T any] interface {
	ExposeSecret() T
}

var (
	_ fmt.Formatter          = (*Boxed[any])(nil)
	_ json.Marshaler         = (*Boxed[any])(nil)
	_ encoding.TextMarshaler = (*Boxed[any])(nil)
)

// Boxed holds a secret value that fmt reflection cannot reach
// even through an unexported struct field.
//
// The zero value is safe: [Boxed.ExposeSecret] returns the zero T.
type Boxed[T any] struct {
	pp **T
}

// New returns a [Boxed] holding a copy of v.
func New[T any](v T) Boxed[T] {
	p := &v
	return Boxed[T]{pp: &p}
}

// ExposeSecret returns the stored value,
// or the zero T if the Boxed is nil or was created with the zero value.
func (b Boxed[T]) ExposeSecret() T {
	if b.pp == nil || *b.pp == nil {
		var z T
		return z
	}
	return **b.pp
}

// Format implements [fmt.Formatter].
func (b Boxed[T]) Format(f fmt.State, c rune) {
	switch v := any(b.ExposeSecret()).(type) {
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
func (b Boxed[T]) MarshalJSON() ([]byte, error) {
	switch v := any(b.ExposeSecret()).(type) {
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
func (b Boxed[T]) MarshalText() (text []byte, err error) {
	switch v := any(b.ExposeSecret()).(type) {
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
