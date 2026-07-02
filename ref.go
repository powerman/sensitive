package sensitive

import (
	"database/sql"
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/shopspring/decimal"
)

var (
	_ fmt.Formatter            = (*Ref[any])(nil)
	_ json.Marshaler           = (*Ref[any])(nil)
	_ encoding.TextMarshaler   = (*Ref[any])(nil)
	_ json.Unmarshaler         = (*Ref[any])(nil)
	_ encoding.TextUnmarshaler = (*Ref[any])(nil)
	_ sql.Scanner              = (*Ref[any])(nil)
)

// Ref holds a secret value that fmt reflection cannot reach,
// and behaves like []byte for equality: == is a compile-time error,
// so an accidental comparison fails loudly instead of silently returning false.
//
// Use Ref in two cases:
//   - the element type's == does not compare by value: []byte, [decimal.Decimal],
//     composite structs.
//     These cannot be a [Handle] element, so they belong here by construction.
//   - the element type's == DOES work by value, but using it is harmful:
//     passwords and hashes are compared constant-time (against another hash),
//     never with ==, so deny == by using Ref[string].
//
// The zero value is safe: [Ref.ExposeSecret] returns the zero T.
//
// == on a Ref, or on any struct containing a Ref field, is a compile-time error.
// Compare values explicitly when needed — [bytes.Equal] for []byte,
// [decimal.Decimal.Equal] for decimals, a constant-time compare for hashes —
// or compare whole structs in tests with [reflect.DeepEqual],
// which reads through Ref and compares by value.
type Ref[T any] struct {
	// Disable ==.
	_ [0]func()
	// While there are other structurally-protected types, the **T is the best:
	// - *any uses extra int storage for the type descriptor;
	// - chan T and func() T breaks [reflect.DeepEqual];
	// - unsafe.Pointer is too complicated (where to keep a secret?) and unsafe to rely on.
	// - *<non-compound> won't work because Ref must also support compound types.
	pp **T
}

// New returns a [Ref] holding a copy of v.
// For string and []byte kinds (including named types), the value is encrypted
// with a random per-process key so a deep-reflection dump reveals only ciphertext.
func New[T any](v T) Ref[T] {
	v = encryptT(v)
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
	return decryptT(**r.pp)
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

// UnmarshalJSON implements [json.Unmarshaler].
func (r *Ref[T]) UnmarshalJSON(data []byte) error {
	var v T
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	*r = New(v)
	return nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
//
//nolint:gocognit,funlen // Inherent complexity: large type switch over all supported primitives.
func (r *Ref[T]) UnmarshalText(text []byte) error {
	var v T
	if tu, ok := any(&v).(encoding.TextUnmarshaler); ok {
		err := tu.UnmarshalText(text)
		if err != nil {
			return err
		}
		*r = New(v)
		return nil
	}
	switch p := any(&v).(type) {
	case *string:
		*p = string(text)
	case *[]byte:
		*p = append([]byte(nil), text...)
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
	*r = New(v)
	return nil
}

// Scan implements [database/sql.Scanner].
//
//nolint:gocognit,funlen // Inherent complexity: large type switch over all supported primitives.
func (r *Ref[T]) Scan(src any) error {
	var v T
	if sc, ok := any(&v).(sql.Scanner); ok {
		err := sc.Scan(src)
		if err != nil {
			return err
		}
		*r = New(v)
		return nil
	}
	if src == nil {
		*r = Ref[T]{}
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
	case *[]byte:
		switch s := src.(type) {
		case []byte:
			cp := make([]byte, len(s))
			copy(cp, s)
			*p = cp
		case string:
			*p = []byte(s)
		default:
			return fmt.Errorf("sensitive: cannot Scan %T into []byte: %w", src, errScanConversion)
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
	*r = New(v)
	return nil
}

// ExposeSecretValuer returns a [SecretValuer] that implements [database/sql/driver.Valuer].
// Use this at the call site to pass the secret to a database driver explicitly.
func (r Ref[T]) ExposeSecretValuer() SecretValuer[T] {
	return SecretValuer[T]{Ref: r}
}
