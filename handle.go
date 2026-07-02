package sensitive

import (
	"database/sql"
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
	"unique"
)

// Comparable is the element-type constraint for [Handle]:
// the primitive comparable types whose native == compares by value.
// It excludes [decimal.Decimal], []byte, and composite structs on purpose — see [Handle].
type Comparable interface {
	// Besides enabling value ==, this constraint is a fmt-safety invariant.
	// [Handle] stores T behind a single *T (via [unique.Handle]);
	// fmt prints that pointer as an address for primitive T,
	// but dereferences it and prints the contents for a struct/slice/array/map T
	// (e.g. under %s/%q — because it triggers "badVerb").
	// Adding a compound-kind T here would let the secret leak through an unexported field.
	//
	// If Comparable is ever extended to such a type, it would be list of concrete types
	// (not an abstract widening) — e.g. a struct-based type like [decimal.Decimal]
	// but WITHOUT an internal pointer, with honest value-==.
	// Then [Handle] MUST be changed to store that T behind an extra indirection
	// (nesting [unique.Handle] one level deeper: unique.Handle[unique.Handle[T]])
	// so the pointer fmt reaches never points directly at compound data
	// (the lint-sensitive safety net is expected to flag the leak otherwise).
	// That nesting is deferred — it is overkill today, and there is a high probability
	// no compound type is ever added to Comparable.
	~string | ~bool |
		~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

var (
	_ fmt.Formatter            = Handle[string]{}
	_ json.Marshaler           = Handle[string]{}
	_ encoding.TextMarshaler   = Handle[string]{}
	_ json.Unmarshaler         = (*Handle[string])(nil)
	_ encoding.TextUnmarshaler = (*Handle[string])(nil)
	_ sql.Scanner              = (*Handle[string])(nil)
)

// Handle holds a secret value that behaves like string for equality:
// == compares by value and a Handle is a valid map key,
// while the value stays unreachable by fmt reflection.
//
// Use Handle for value-comparable secrets where == is not harmful:
// bearer tokens, session IDs, refresh tokens, API keys —
// anything you would naturally hold as a string or number and might compare or index.
// Do NOT use Handle for passwords or hashes even though they are strings:
// == on them is an anti-pattern (compare hashes constant-time), so use [Ref].
//
// Equal values are canonicalized to a single pointer via the runtime's
// unique-handle intern pool, so == and map lookups work by value.
// Making a Handle inserts the value into a process-global intern table;
// the entry is held weakly and is reclaimed when no Handle refers to it.
//
// T must be one of the primitive comparable types listed in [Comparable]
// (string, bool, integers, floats, and named types over them).
// [decimal.Decimal], []byte, and composite structs are rejected at compile time
// because their native == compares pointer identity, not value — use [Ref] for those.
//
// The zero value is safe: [Handle.ExposeSecret] returns the zero T.
type Handle[T Comparable] struct{ h unique.Handle[T] }

// Make returns a [Handle] holding v.
// Equal values are canonicalized to a single pointer via
// the runtime's unique-handle intern pool,
// so == and map lookups work by value.
// Making a Handle inserts v into a process-global weak intern table;
// the entry is reclaimed when no Handle refers to it.
func Make[T Comparable](v T) Handle[T] { return Handle[T]{h: unique.Make(v)} }

// ExposeSecret returns the stored value, or the zero T for the zero-value Handle.
func (h Handle[T]) ExposeSecret() T {
	// A raw [unique.Handle.Value] panics on the zero value;
	// Handle guards against this so its zero value is safe, matching [Ref].
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

// UnmarshalJSON implements [json.Unmarshaler].
func (h *Handle[T]) UnmarshalJSON(data []byte) error {
	var v T
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	*h = Make(v)
	return nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
//
//nolint:gocognit,funlen // Inherent complexity: large type switch over all supported primitives.
func (h *Handle[T]) UnmarshalText(text []byte) error {
	var v T
	if tu, ok := any(&v).(encoding.TextUnmarshaler); ok {
		err := tu.UnmarshalText(text)
		if err != nil {
			return err
		}
		*h = Make(v)
		return nil
	}
	switch p := any(&v).(type) {
	case *string:
		*p = string(text)
	case *bool:
		b, err := strconv.ParseBool(string(text))
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into bool: %w", errTextSyntax)
		}
		*p = b
	case *int:
		n, err := strconv.ParseInt(string(text), base10, 0)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into int: %w", errTextSyntax)
		}
		*p = int(n)
	case *int8:
		n, err := strconv.ParseInt(string(text), base10, bits8)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into int8: %w", errTextSyntax)
		}
		*p = int8(n)
	case *int16:
		n, err := strconv.ParseInt(string(text), base10, bits16)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into int16: %w", errTextSyntax)
		}
		*p = int16(n)
	case *int32:
		n, err := strconv.ParseInt(string(text), base10, bits32)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into int32: %w", errTextSyntax)
		}
		*p = int32(n)
	case *int64:
		n, err := strconv.ParseInt(string(text), base10, bits64)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into int64: %w", errTextSyntax)
		}
		*p = n
	case *uint:
		n, err := strconv.ParseUint(string(text), base10, 0)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into uint: %w", errTextSyntax)
		}
		*p = uint(n)
	case *uint8:
		n, err := strconv.ParseUint(string(text), base10, bits8)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into uint8: %w", errTextSyntax)
		}
		*p = uint8(n)
	case *uint16:
		n, err := strconv.ParseUint(string(text), base10, bits16)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into uint16: %w", errTextSyntax)
		}
		*p = uint16(n)
	case *uint32:
		n, err := strconv.ParseUint(string(text), base10, bits32)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into uint32: %w", errTextSyntax)
		}
		*p = uint32(n)
	case *uint64:
		n, err := strconv.ParseUint(string(text), base10, bits64)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into uint64: %w", errTextSyntax)
		}
		*p = n
	case *float32:
		f, err := strconv.ParseFloat(string(text), bits32)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into float32: %w", errTextSyntax)
		}
		*p = float32(f)
	case *float64:
		f, err := strconv.ParseFloat(string(text), bits64)
		if err != nil {
			return fmt.Errorf("sensitive: cannot unmarshal text into float64: %w", errTextSyntax)
		}
		*p = f
	default:
		return fmt.Errorf("sensitive: UnmarshalText into %T is unsupported: %w", v, errUnsupportedT)
	}
	*h = Make(v)
	return nil
}

// Scan implements [database/sql.Scanner].
//
//nolint:gocognit,funlen // Inherent complexity: large type switch over all supported primitives.
func (h *Handle[T]) Scan(src any) error {
	var v T
	if sc, ok := any(&v).(sql.Scanner); ok {
		err := sc.Scan(src)
		if err != nil {
			return err
		}
		*h = Make(v)
		return nil
	}
	if src == nil {
		*h = Handle[T]{}
		return nil
	}
	switch p := any(&v).(type) {
	case *string:
		switch s := src.(type) {
		case string:
			*p = s
		case []byte:
			*p = string(s)
		default:
			return fmt.Errorf("sensitive: cannot Scan %T into string: %w", src, errScanConversion)
		}
	case *bool:
		switch s := src.(type) {
		case bool:
			*p = s
		case int64:
			*p = s != 0
		default:
			return fmt.Errorf("sensitive: cannot Scan %T into bool: %w", src, errScanConversion)
		}
	case *int:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into int: %w", src, errScanConversion)
		}
		*p = int(s)
	case *int8:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into int8: %w", src, errScanConversion)
		}
		*p = int8(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *int16:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into int16: %w", src, errScanConversion)
		}
		*p = int16(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *int32:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into int32: %w", src, errScanConversion)
		}
		*p = int32(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *int64:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into int64: %w", src, errScanConversion)
		}
		*p = s
	case *uint:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into uint: %w", src, errScanConversion)
		}
		*p = uint(s) //nolint:gosec // G115: negative DB value wraps; caller controls DB schema.
	case *uint8:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into uint8: %w", src, errScanConversion)
		}
		*p = uint8(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *uint16:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into uint16: %w", src, errScanConversion)
		}
		*p = uint16(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *uint32:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into uint32: %w", src, errScanConversion)
		}
		*p = uint32(s) //nolint:gosec // G115: truncation accepted; caller controls DB schema.
	case *uint64:
		s, ok := src.(int64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into uint64: %w", src, errScanConversion)
		}
		*p = uint64(s) //nolint:gosec // G115: negative DB value wraps; caller controls DB schema.
	case *float32:
		s, ok := src.(float64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into float32: %w", src, errScanConversion)
		}
		*p = float32(s)
	case *float64:
		s, ok := src.(float64)
		if !ok {
			return fmt.Errorf("sensitive: cannot Scan %T into float64: %w", src, errScanConversion)
		}
		*p = s
	default:
		return fmt.Errorf("sensitive: Scan into %T is unsupported: %w", v, errUnsupportedT)
	}
	*h = Make(v)
	return nil
}

// ExposeSecretValuer returns a [SecretValuer] that implements [database/sql/driver.Valuer].
// Use this at the call site to pass the secret to a database driver explicitly.
func (h Handle[T]) ExposeSecretValuer() SecretValuer[T] {
	return SecretValuer[T]{Ref: New(h.ExposeSecret())}
}
