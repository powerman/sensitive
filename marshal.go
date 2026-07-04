package sensitive

import (
	"encoding/json"
	"math"
	"strconv"

	"github.com/shopspring/decimal"
)

// marshal helpers for Bool.

func marshalJSONBool(v bool) ([]byte, error) {
	var ss state
	FormatBoolFn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	b, err := strconv.ParseBool(string(ss.b))
	if err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

func marshalTextBool(v bool) []byte {
	var ss state
	FormatBoolFn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Bytes.

func marshalJSONBytes(v []byte) ([]byte, error) {
	var ss state
	FormatBytesFn(v, &ss, 's')
	return json.Marshal(ss.b)
}

func marshalTextBytes(v []byte) []byte {
	var ss state
	FormatBytesFn(v, &ss, 'X')
	return ss.b
}

// marshal helpers for Decimal.

func marshalJSONDecimal(v decimal.Decimal) ([]byte, error) {
	var ss state
	FormatDecimalFn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	f, err := strconv.ParseFloat(string(ss.b), bits64)
	if err != nil {
		return nil, err
	}
	// NaN/Inf is the redaction sentinel for Decimal (set by Redact()).
	// Standard JSON cannot represent NaN or Inf — json.Marshal would
	// return an error, breaking the surrounding document. A redacted
	// secret must never do that, so we output null instead.
	// Do not remove this guard: it is intentional.
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return json.Marshal(nil)
	}
	return json.Marshal(f)
}

func marshalTextDecimal(v decimal.Decimal) []byte {
	var ss state
	FormatDecimalFn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Float32.

func marshalJSONFloat32(v float32) ([]byte, error) {
	var ss state
	FormatFloat32Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	f, err := strconv.ParseFloat(string(ss.b), bits32)
	if err != nil {
		return nil, err
	}
	ff := float32(f)
	// NaN/Inf is the redaction sentinel for Float32 (set by Redact()).
	// Standard JSON cannot represent NaN or Inf — json.Marshal would
	// return an error, breaking the surrounding document. A redacted
	// secret must never do that, so we output null instead.
	// Do not remove this guard: it is intentional.
	if math.IsNaN(float64(ff)) || math.IsInf(float64(ff), 0) {
		return json.Marshal(nil)
	}
	return json.Marshal(ff)
}

func marshalTextFloat32(v float32) []byte {
	var ss state
	FormatFloat32Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Float64.

func marshalJSONFloat64(v float64) ([]byte, error) {
	var ss state
	FormatFloat64Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	f, err := strconv.ParseFloat(string(ss.b), bits64)
	if err != nil {
		return nil, err
	}
	// NaN/Inf is the redaction sentinel for Float64 (set by Redact()).
	// Standard JSON cannot represent NaN or Inf — json.Marshal would
	// return an error, breaking the surrounding document. A redacted
	// secret must never do that, so we output null instead.
	// Do not remove this guard: it is intentional.
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return json.Marshal(nil)
	}
	return json.Marshal(f)
}

func marshalTextFloat64(v float64) []byte {
	var ss state
	FormatFloat64Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Int.

func marshalJSONInt(v int) ([]byte, error) {
	var ss state
	FormatIntFn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseInt(string(ss.b), base10, 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int(n))
}

func marshalTextInt(v int) []byte {
	var ss state
	FormatIntFn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Int8.

func marshalJSONInt8(v int8) ([]byte, error) {
	var ss state
	FormatInt8Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseInt(string(ss.b), base10, bits8)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int8(n))
}

func marshalTextInt8(v int8) []byte {
	var ss state
	FormatInt8Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Int16.

func marshalJSONInt16(v int16) ([]byte, error) {
	var ss state
	FormatInt16Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseInt(string(ss.b), base10, bits16)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int16(n))
}

func marshalTextInt16(v int16) []byte {
	var ss state
	FormatInt16Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Int32.

func marshalJSONInt32(v int32) ([]byte, error) {
	var ss state
	FormatInt32Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseInt(string(ss.b), base10, bits32)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int32(n))
}

func marshalTextInt32(v int32) []byte {
	var ss state
	FormatInt32Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Int64.

func marshalJSONInt64(v int64) ([]byte, error) {
	var ss state
	FormatInt64Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseInt(string(ss.b), base10, bits64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(n)
}

func marshalTextInt64(v int64) []byte {
	var ss state
	FormatInt64Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for String.

func marshalJSONString(v string) ([]byte, error) {
	var ss state
	FormatStringFn(v, &ss, 'v')
	return json.Marshal(string(ss.b))
}

func marshalTextString(v string) []byte {
	var ss state
	FormatStringFn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Uint.

func marshalJSONUint(v uint) ([]byte, error) {
	var ss state
	FormatUintFn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseUint(string(ss.b), base10, 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint(n))
}

func marshalTextUint(v uint) []byte {
	var ss state
	FormatUintFn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Uint8.

func marshalJSONUint8(v uint8) ([]byte, error) {
	var ss state
	FormatUint8Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseUint(string(ss.b), base10, bits8)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint8(n))
}

func marshalTextUint8(v uint8) []byte {
	var ss state
	FormatUint8Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Uint16.

func marshalJSONUint16(v uint16) ([]byte, error) {
	var ss state
	FormatUint16Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseUint(string(ss.b), base10, bits16)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint16(n))
}

func marshalTextUint16(v uint16) []byte {
	var ss state
	FormatUint16Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Uint32.

func marshalJSONUint32(v uint32) ([]byte, error) {
	var ss state
	FormatUint32Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseUint(string(ss.b), base10, bits32)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint32(n))
}

func marshalTextUint32(v uint32) []byte {
	var ss state
	FormatUint32Fn(v, &ss, 'v')
	return ss.b
}

// marshal helpers for Uint64.

func marshalJSONUint64(v uint64) ([]byte, error) {
	var ss state
	FormatUint64Fn(v, &ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	n, err := strconv.ParseUint(string(ss.b), base10, bits64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(n)
}

func marshalTextUint64(v uint64) []byte {
	var ss state
	FormatUint64Fn(v, &ss, 'v')
	return ss.b
}
