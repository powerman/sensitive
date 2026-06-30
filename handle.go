package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"unique"
)

// Comparable is the element-type constraint for [Handle]:
// the primitive comparable types whose native == compares by value.
// It excludes decimal.Decimal, []byte, and composite structs on purpose — see [Handle].
type Comparable interface {
	// Maintainer invariant (not part of the public API contract):
	// besides enabling value ==, this constraint is a fmt-safety invariant.
	// [Handle] stores T behind a single *T (via [unique.Handle]);
	// fmt prints that pointer as an address for primitive T,
	// but dereferences it and prints the contents for a struct/slice/array/map T
	// (e.g. under %s/%q - because it triggers "badVerb").
	// Adding a compound-kind T here would let the secret leak through an unexported field.
	// If Comparable is ever extended to such a type,
	// [Handle] must store that T behind an extra indirection
	// (e.g. by nesting [unique.Handle] one level deeper)
	// so the pointer fmt reaches never points directly at compound data;
	// the lint-sensitive safety net is expected to flag the leak otherwise.
	~string | ~bool |
		~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

var (
	_ fmt.Formatter          = Handle[string]{}
	_ json.Marshaler         = Handle[string]{}
	_ encoding.TextMarshaler = Handle[string]{}
)

// Handle holds a secret value that behaves like string for equality: ==
// compares by value and a Handle is a valid map key, while the value stays
// unreachable by fmt reflection.
//
// Use Handle for value-comparable secrets where == is not harmful: bearer
// tokens, session IDs, refresh tokens, API keys — anything you would
// naturally hold as a string or number and might compare or index. Do NOT
// use Handle for passwords or hashes even though they are strings: == on
// them is an anti-pattern (compare hashes constant-time), so use [Ref].
//
// Equal values are canonicalized to a single pointer via the runtime's
// unique-handle intern pool, so == and map lookups work by value. Making a
// Handle inserts the value into a process-global intern table; the entry is
// held weakly and is reclaimed when no Handle refers to it.
//
// T must be one of the primitive comparable types listed in [Comparable]
// (string, bool, integers, floats, and named types over them).
// decimal.Decimal, []byte, and composite structs are rejected at compile
// time because their native == compares pointer identity, not value — use
// [Ref] for those.
//
// The zero value is safe: [Handle.ExposeSecret] returns the zero T.
type Handle[T Comparable] struct{ h unique.Handle[T] }

// Make returns a [Handle] holding v. Equal values are canonicalized to a
// single pointer via the runtime's unique-handle intern pool, so == and map
// lookups work by value. Making a Handle inserts v into a process-global
// weak intern table; the entry is reclaimed when no Handle refers to it.
func Make[T Comparable](v T) Handle[T] { return Handle[T]{h: unique.Make(v)} }

// ExposeSecret returns the stored value, or the zero T for the zero-value
// Handle. (A raw unique.Handle.Value panics on the zero value; Handle
// guards against this so its zero value is safe, matching [Ref].)
func (h Handle[T]) ExposeSecret() T {
	if h.h == (unique.Handle[T]{}) {
		var z T
		return z
	}
	return h.h.Value()
}

// Format implements [fmt.Formatter].
func (h Handle[T]) Format(f fmt.State, c rune) {
	switch v := any(h.ExposeSecret()).(type) {
	case bool:
		FormatBoolFn(Bool(v), f, c)
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
func (h Handle[T]) MarshalJSON() ([]byte, error) {
	switch v := any(h.ExposeSecret()).(type) {
	case bool:
		return Bool(v).MarshalJSON()
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
func (h Handle[T]) MarshalText() (text []byte, err error) {
	switch v := any(h.ExposeSecret()).(type) {
	case bool:
		return Bool(v).MarshalText()
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
