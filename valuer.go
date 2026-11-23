package sensitive

import (
	"database/sql"
	"database/sql/driver"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
)

var (
	_ driver.Valuer            = SecretValuer[any]{}
	_ json.Marshaler           = SecretValuer[any]{}
	_ encoding.TextMarshaler   = SecretValuer[any]{}
	_ slog.LogValuer           = SecretValuer[any]{}
	_ fmt.Formatter            = SecretValuer[any]{}
	_ json.Unmarshaler         = (*SecretValuer[any])(nil)
	_ encoding.TextUnmarshaler = (*SecretValuer[any])(nil)
	_ sql.Scanner              = (*SecretValuer[any])(nil)
)

// SecretValuer wraps a [Ref][T] to implement EXPOSING secret value
// [driver.Valuer], [json.Marshaler], and [encoding.TextMarshaler],
// while remaining redaction-safe under [fmt] and structured logging ([slog]).
//
// It is the explicit way to pass a secret to a trusted sink:
// a database driver, JSON serialization for the wire, or text encoding.
// The secret is exposed ONLY when one of the following is called:
//   - [driver.Valuer.Value]                — database driver.
//   - [json.Marshaler.MarshalJSON]         — JSON serialization.
//   - [encoding.TextMarshaler.MarshalText] — text encoding.
//
// SecretValuer is redaction-safe under [fmt] and [slog]:
//   - [fmt.Formatter.Format] produces redacted output.
//   - [slog.LogValuer.LogValue] returns a type-preserving redacted value,
//     so neither [slog.JSONHandler] nor [slog.TextHandler] can leak the secret,
//     even though this same type also exposes it under [json.Marshal]
//     and [encoding.TextMarshaler].
//
// Ingress methods ([json.Unmarshaler], [encoding.TextUnmarshaler],
// [database/sql.Scanner]) receive and protect the secret just like [Ref],
// making SecretValuer suitable for combined egress+ingress (round-trip) DTOs.
//
// SecretValuer is INERT: it never exposes the raw secret directly.
// To leave the egress/round-trip boundary, call [SecretValuer.ToRef].
// Keep SecretValuer confined to the egress/round-trip DTO;
// do not carry it deeper into the application.
// Unlike [driver.Valuer], [json.Marshal] and [encoding.TextMarshaler]
// are called by any encoder that finds this type on an exported field —
// not only the intended one.
type SecretValuer[T any] struct {
	ref Ref[T]
}

// Value implements [driver.Valuer].
// It exposes the underlying secret as a database driver value.
func (sv SecretValuer[T]) Value() (driver.Value, error) {
	v := sv.ref.ExposeSecret()
	if vr, ok := any(v).(driver.Valuer); ok {
		return vr.Value()
	}
	switch u := underlying(v).(type) {
	case string:
		return u, nil
	case []byte:
		return u, nil
	case bool:
		return u, nil
	case int:
		return int64(u), nil
	case int8:
		return int64(u), nil
	case int16:
		return int64(u), nil
	case int32:
		return int64(u), nil
	case int64:
		return u, nil
	case uint:
		return int64(u), nil //nolint:gosec // G115: driver.Value requires int64; large values overflow silently.
	case uint8:
		return int64(u), nil
	case uint16:
		return int64(u), nil
	case uint32:
		return int64(u), nil
	case uint64:
		return int64(u), nil //nolint:gosec // G115: driver.Value requires int64; large values overflow silently.
	case float32:
		return float64(u), nil
	case float64:
		return u, nil
	default:
		return nil, fmt.Errorf("sensitive: Value for %T is unsupported: %w", v, errUnsupportedT)
	}
}

// MarshalJSON implements [json.Marshaler].
// It exposes the underlying secret as JSON.
func (sv SecretValuer[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(sv.ref.ExposeSecret())
}

// MarshalText implements [encoding.TextMarshaler].
// It exposes the underlying secret as text.
func (sv SecretValuer[T]) MarshalText() ([]byte, error) {
	v := sv.ref.ExposeSecret()
	if tm, ok := any(v).(encoding.TextMarshaler); ok {
		return tm.MarshalText()
	}
	switch u := underlying(v).(type) {
	case string:
		return []byte(u), nil
	case []byte:
		return u, nil
	case bool:
		return strconv.AppendBool(nil, u), nil
	case int:
		return strconv.AppendInt(nil, int64(u), base10), nil
	case int8:
		return strconv.AppendInt(nil, int64(u), base10), nil
	case int16:
		return strconv.AppendInt(nil, int64(u), base10), nil
	case int32:
		return strconv.AppendInt(nil, int64(u), base10), nil
	case int64:
		return strconv.AppendInt(nil, u, base10), nil
	case uint:
		return strconv.AppendUint(nil, uint64(u), base10), nil
	case uint8:
		return strconv.AppendUint(nil, uint64(u), base10), nil
	case uint16:
		return strconv.AppendUint(nil, uint64(u), base10), nil
	case uint32:
		return strconv.AppendUint(nil, uint64(u), base10), nil
	case uint64:
		return strconv.AppendUint(nil, u, base10), nil
	case float32:
		return strconv.AppendFloat(nil, float64(u), 'g', -1, bits32), nil
	case float64:
		return strconv.AppendFloat(nil, u, 'g', -1, bits64), nil
	default:
		return nil, fmt.Errorf("sensitive: MarshalText for %T is unsupported: %w", v, errUnsupportedT)
	}
}

// LogValue implements [slog.LogValuer].
// It follows the same Format<Type>Fn policy as [Ref.LogValue],
// so structured loggers never expose the secret.
func (sv SecretValuer[T]) LogValue() slog.Value { return sv.ref.LogValue() }

// Format implements [fmt.Formatter].
// It produces redacted output so the secret never appears in formatted strings.
func (sv SecretValuer[T]) Format(f fmt.State, c rune) { sv.ref.Format(f, c) }

// IsZero reports whether the underlying [Ref] holds the zero value.
func (sv SecretValuer[T]) IsZero() bool { return sv.ref.IsZero() }

// ToRef returns the secret held as a redaction-safe [Ref],
// the explicit way to leave the egress/ingress boundary.
// To obtain a [Handle], use [Make](sv.ToRef().ExposeSecret()).
func (sv SecretValuer[T]) ToRef() Ref[T] { return sv.ref }

// UnmarshalJSON implements [json.Unmarshaler].
func (sv *SecretValuer[T]) UnmarshalJSON(b []byte) error { return sv.ref.UnmarshalJSON(b) }

// UnmarshalText implements [encoding.TextUnmarshaler].
func (sv *SecretValuer[T]) UnmarshalText(text []byte) error { return sv.ref.UnmarshalText(text) }

// Scan implements [database/sql.Scanner].
func (sv *SecretValuer[T]) Scan(src any) error { return sv.ref.Scan(src) }
