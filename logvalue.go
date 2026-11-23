package sensitive

import (
	"encoding/json"
	"log/slog"
	"math"
	"strconv"

	"github.com/shopspring/decimal"
)

// logValue returns the value to log for the secret v
// according to the current Format<type>Fn policy.
//
// The value is parsed back from the text printed by Format<type>Fn,
// so the policy is the same as for fmt and the marshalers.
// Exactness is not required here (logs are not an egress sink),
// but the JSON type of the field is preserved when the text is a literal of the type.
// Text which is not such a literal (a custom Format<type>Fn output) is logged as a string.
// NaN, Inf and an unsupported type are logged as nil:
// [slog.Float64Value](NaN) would make [slog.JSONHandler] fail with !ERROR.
//
//nolint:funlen // A flat type switch over all supported types is the clearest form.
func logValue(v any) slog.Value {
	switch v := v.(type) {
	case bool:
		text := string(marshalTextBool(v))
		b, err := strconv.ParseBool(text)
		if err != nil {
			return slog.StringValue(text)
		}
		return slog.BoolValue(b)
	case []byte:
		var raw, text state
		FormatBytesFn(v, &raw, 's')
		FormatBytesFn(v, &text, 'X')
		return slog.AnyValue(logBytes{raw: raw.b, text: text.b})
	case decimal.Decimal:
		text := string(marshalTextDecimal(v))
		d, err := decimal.NewFromString(text)
		if err != nil {
			return slog.StringValue(text)
		}
		return slog.AnyValue(d)
	case float32:
		return logFloat(marshalTextFloat32(v))
	case float64:
		return logFloat(marshalTextFloat64(v))
	case string:
		return slog.StringValue(string(marshalTextString(v)))
	case int:
		return logInt(marshalTextInt(v), 0)
	case int8:
		return logInt(marshalTextInt8(v), bits8)
	case int16:
		return logInt(marshalTextInt16(v), bits16)
	case int32:
		return logInt(marshalTextInt32(v), bits32)
	case int64:
		return logInt(marshalTextInt64(v), bits64)
	case uint:
		return logUint(marshalTextUint(v), 0)
	case uint8:
		return logUint(marshalTextUint8(v), bits8)
	case uint16:
		return logUint(marshalTextUint16(v), bits16)
	case uint32:
		return logUint(marshalTextUint32(v), bits32)
	case uint64:
		return logUint(marshalTextUint64(v), bits64)
	default:
		return slog.AnyValue(nil)
	}
}

// logBytes keeps both representations of a []byte secret printed by FormatBytesFn,
// so every slog handler renders it the same way as Ref does:
// as text it is the 'X' form (always valid UTF-8, e.g. DEFACE),
// as JSON it is the base64 of the 's' form, like [json.Marshal] does for []byte.
// Without this type a handler would choose between raw bytes and base64 on its own.
type logBytes struct {
	raw  []byte
	text []byte
}

// MarshalText implements [encoding.TextMarshaler].
func (b logBytes) MarshalText() ([]byte, error) { return b.text, nil }

// MarshalJSON implements [json.Marshaler].
func (b logBytes) MarshalJSON() ([]byte, error) { return json.Marshal(b.raw) }

func logFloat(text []byte) slog.Value {
	f, err := strconv.ParseFloat(string(text), bits64)
	if err != nil {
		return slog.StringValue(string(text))
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return slog.AnyValue(nil)
	}
	return slog.Float64Value(f)
}

func logInt(text []byte, bitSize int) slog.Value {
	n, err := strconv.ParseInt(string(text), base10, bitSize)
	if err != nil {
		return slog.StringValue(string(text))
	}
	return slog.Int64Value(n)
}

func logUint(text []byte, bitSize int) slog.Value {
	n, err := strconv.ParseUint(string(text), base10, bitSize)
	if err != nil {
		return slog.StringValue(string(text))
	}
	return slog.Uint64Value(n)
}
