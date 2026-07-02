package sensitive

import (
	"database/sql/driver"
	"fmt"
)

var _ driver.Valuer = SecretValuer[any]{}

// SecretValuer wraps [Ref][T] to implement [driver.Valuer].
// It is the explicit way to pass a Ref secret to a database driver.
// SecretValuer itself is redaction-safe: formatting or marshaling it never leaks the secret.
type SecretValuer[T any] struct{ Ref[T] }

// Value implements [driver.Valuer].
func (sv SecretValuer[T]) Value() (driver.Value, error) {
	v := sv.ExposeSecret()
	if vr, ok := any(v).(driver.Valuer); ok {
		return vr.Value()
	}
	switch u := any(v).(type) {
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
