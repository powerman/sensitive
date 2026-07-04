package sensitive_test

import (
	"encoding"
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

// namedString is a named type over string, used to test that Handle
// works with named Comparable types.
type namedString string

// structWithUnexportedHandle holds Handle values in unexported fields.
type structWithUnexportedHandle struct {
	s  sensitive.Handle[string]
	st sensitive.Handle[int]
}

// structWithInterfaceHoldingHandle holds an interface containing a Handle
// in an unexported field.
type structWithInterfaceHoldingHandle struct {
	v any
}

func TestHandle_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := "my-handle-secret"
	h := sensitive.Make(secret)

	tests := []struct {
		name       string
		formatting string
		value      any
		notWant    string
	}{
		{name: "Handle[string] %s", formatting: "%s", value: h, notWant: secret},
		{name: "Handle[string] %q", formatting: "%q", value: h, notWant: secret},
		{name: "Handle[string] %v", formatting: "%v", value: h, notWant: secret},
		{name: "Handle[string] %+v", formatting: "%+v", value: h, notWant: secret},
		{name: "Handle[string] %#v", formatting: "%#v", value: h, notWant: secret},
		{name: "Handle[string] %x", formatting: "%x", value: h, notWant: secret},
		{name: "Handle[string] %X", formatting: "%X", value: h, notWant: secret},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			t.NotContains(fmt.Sprintf(tc.formatting, tc.value), tc.notWant)
		})
	}
}

func TestHandle_formatting_allTypes(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}

	type testCase struct {
		name   string
		secret any
		handle any
	}

	// Use a helper that produces a Handle[T] for each numeric type.
	tests := []testCase{
		{name: "bool", secret: true, handle: sensitive.Make(true)},
		{name: "string", secret: "my-secret", handle: sensitive.Make("my-secret")},
		{name: "int", secret: 42, handle: sensitive.Make(42)},
		{name: "int8", secret: int8(-128), handle: sensitive.Make(int8(-128))},
		{name: "int16", secret: int16(32767), handle: sensitive.Make(int16(32767))},
		{name: "int32", secret: int32(-2147483648), handle: sensitive.Make(int32(-2147483648))},
		{name: "int64", secret: int64(-1), handle: sensitive.Make(int64(-1))},
		{name: "uint", secret: uint(0), handle: sensitive.Make(uint(0))},
		{name: "uint8", secret: uint8(255), handle: sensitive.Make(uint8(255))},
		{name: "uint16", secret: uint16(65535), handle: sensitive.Make(uint16(65535))},
		{name: "uint32", secret: uint32(4294967295), handle: sensitive.Make(uint32(4294967295))},
		{name: "uint64", secret: uint64(math.MaxUint64), handle: sensitive.Make(uint64(math.MaxUint64))},
		{name: "float32", secret: float32(3.14), handle: sensitive.Make(float32(3.14))},
		{name: "float64", secret: 2.718, handle: sensitive.Make(2.718)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)

			for _, verb := range verbs {
				result := fmt.Sprintf(verb, tc.handle)
				t.NotContains(result, fmt.Sprintf("%v", tc.secret),
					"%s formatting of Handle[%T] must not leak the secret", verb, tc.secret)
			}
		})
	}
}

func TestHandle_valueEquality(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	a := sensitive.Make("hello")
	b := sensitive.Make("hello")
	c := sensitive.Make("world")

	t.True(a == b, "equal values should produce equal handles")
	t.True(a != c, "different values should produce different handles")
}

func TestHandle_mapKey(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	m := map[sensitive.Handle[string]]int{
		sensitive.Make("hello"): 1,
		sensitive.Make("world"): 2,
	}

	t.Equal(m[sensitive.Make("hello")], 1, "map lookup by equal value should find the entry")
	t.Equal(m[sensitive.Make("world")], 2, "map lookup by equal value should find the entry")

	_, found := m[sensitive.Make("nonexistent")]
	t.False(found, "map lookup by missing value should not find anything")
}

func TestHandle_deepEqual(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	a := sensitive.Make("x")
	b := sensitive.Make("x")

	t.True(equal(a, b), "DeepEqual Handle[string] with same value")

	a2 := sensitive.Make("alpha")
	b2 := sensitive.Make("beta")
	t.False(equal(a2, b2), "DeepEqual Handle[string] with different values")
}

func TestHandle_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("round_trip", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		h := sensitive.Make("handle-data")
		t.Equal(h.ExposeSecret(), "handle-data")
	})

	t.Run("zero_value_safe", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var z sensitive.Handle[string]
		t.NotPanic(func() { _ = z.ExposeSecret() },
			"zero value Handle must not panic on ExposeSecret")
		t.Equal(z.ExposeSecret(), "")
	})
}

func TestHandle_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Make("my-json-value")

	result, err := json.Marshal(value)
	t.Nil(err)
	t.NotContains(string(result), "my-json-value")
}

func TestHandle_marshalJSON_exactOutput(tt *testing.T) {
	t := check.T(tt).MustAll()

	tt.Setenv("GO_TEST_DISABLE_SENSITIVE", "1")
	sensitive.Disable()
	t.Cleanup(resetFormatFns)

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "bool", value: sensitive.Make(true), want: `true`},
		{name: "float32", value: sensitive.Make(float32(3.14)), want: `3.14`},
		{name: "float64", value: sensitive.Make(2.718), want: `2.718`},
		{name: "int", value: sensitive.Make(42), want: `42`},
		{name: "int8", value: sensitive.Make(int8(-128)), want: `-128`},
		{name: "int16", value: sensitive.Make(int16(32767)), want: `32767`},
		{name: "int32", value: sensitive.Make(int32(-2147483648)), want: `-2147483648`},
		{name: "int64", value: sensitive.Make(int64(-1)), want: `-1`},
		{name: "string", value: sensitive.Make("hello"), want: `"hello"`},
		{name: "uint", value: sensitive.Make(uint(0)), want: `0`},
		{name: "uint8", value: sensitive.Make(uint8(255)), want: `255`},
		{name: "uint16", value: sensitive.Make(uint16(65535)), want: `65535`},
		{name: "uint32", value: sensitive.Make(uint32(4294967295)), want: `4294967295`},
		{name: "uint64", value: sensitive.Make(uint64(math.MaxUint64)), want: `18446744073709551615`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			t := check.T(tt)

			got, err := json.Marshal(tc.value)
			t.Nil(err, "MarshalJSON should not error")
			t.Equal(string(got), tc.want)
		})
	}
}

func TestHandle_marshalText_exactOutput(tt *testing.T) {
	t := check.T(tt).MustAll()

	tt.Setenv("GO_TEST_DISABLE_SENSITIVE", "1")
	sensitive.Disable()
	t.Cleanup(resetFormatFns)

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "bool", value: sensitive.Make(true), want: "true"},
		{name: "float32", value: sensitive.Make(float32(3.14)), want: "3.14"},
		{name: "float64", value: sensitive.Make(2.718), want: "2.718"},
		{name: "int", value: sensitive.Make(42), want: "42"},
		{name: "int8", value: sensitive.Make(int8(-128)), want: "-128"},
		{name: "int16", value: sensitive.Make(int16(32767)), want: "32767"},
		{name: "int32", value: sensitive.Make(int32(-2147483648)), want: "-2147483648"},
		{name: "int64", value: sensitive.Make(int64(-1)), want: "-1"},
		{name: "string", value: sensitive.Make("hello"), want: "hello"},
		{name: "uint", value: sensitive.Make(uint(0)), want: "0"},
		{name: "uint8", value: sensitive.Make(uint8(255)), want: "255"},
		{name: "uint16", value: sensitive.Make(uint16(65535)), want: "65535"},
		{name: "uint32", value: sensitive.Make(uint32(4294967295)), want: "4294967295"},
		{name: "uint64", value: sensitive.Make(uint64(math.MaxUint64)), want: "18446744073709551615"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			t := check.T(tt)

			tm, ok := tc.value.(encoding.TextMarshaler)
			t.True(ok, "Handle should implement encoding.TextMarshaler")
			got, err := tm.MarshalText()
			t.Nil(err, "MarshalText should not error")
			t.Equal(string(got), tc.want)
		})
	}
}

func TestHandle_reflectionSafety(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secretStr := "hidden-handle-secret"
	secretInt := 42

	parent := structWithUnexportedHandle{
		s:  sensitive.Make(secretStr),
		st: sensitive.Make(secretInt),
	}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}

	for _, verb := range verbs {
		t.Run("unexported_field_"+verb, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)

			result := fmt.Sprintf(verb, parent)

			t.NotContains(result, secretStr,
				"secret string should not appear in %s formatting", verb)
		})
	}
}

func TestHandle_interfaceInUnexportedField(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := "hidden-behind-interface-handle"
	h := sensitive.Make(secret)

	parent := structWithInterfaceHoldingHandle{
		v: h,
	}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}

	for _, verb := range verbs {
		t.Run("interface_unexported_"+verb, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)

			result := fmt.Sprintf(verb, parent)

			t.NotContains(result, secret,
				"secret should not appear in %s formatting", verb)
		})
	}
}

func TestHandle_namedType(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	v := namedString("my-token")
	h := sensitive.Make(v)

	t.True(h.ExposeSecret() == namedString("my-token"), "named type should round-trip")
	t.True(sensitive.Make(v) == h, "named types should compare equal by value")
}

func TestHandle_zeroValue(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("format_no_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		t.NotPanic(func() {
			_ = fmt.Sprintf("%v", sensitive.Handle[string]{})
		})
	})
}

func TestHandle_UnmarshalJSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.Nil(json.Unmarshal([]byte(`"hello"`), &h))
		t.Equal(h.ExposeSecret(), "hello")
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int]
		t.Nil(json.Unmarshal([]byte(`42`), &h))
		t.Equal(h.ExposeSecret(), 42)
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[bool]
		t.Nil(json.Unmarshal([]byte(`true`), &h))
		t.Equal(h.ExposeSecret(), true)
	})

	t.Run("invalid_json", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.NotNil(json.Unmarshal([]byte(`not json`), &h))
	})
}

func TestHandle_UnmarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.Nil(h.UnmarshalText([]byte("hello")))
		t.Equal(h.ExposeSecret(), "hello")
	})

	t.Run("bool_false", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[bool]
		t.Nil(h.UnmarshalText([]byte("false")))
		t.Equal(h.ExposeSecret(), false)
	})

	t.Run("bool_invalid", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[bool]
		t.NotNil(h.UnmarshalText([]byte("notabool")))
	})

	t.Run("int64_negative", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int64]
		t.Nil(h.UnmarshalText([]byte("-9223372036854775808")))
		t.Equal(h.ExposeSecret(), int64(math.MinInt64))
	})

	t.Run("uint64_max", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint64]
		t.Nil(h.UnmarshalText([]byte("18446744073709551615")))
		t.Equal(h.ExposeSecret(), uint64(math.MaxUint64))
	})

	t.Run("float32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float32]
		t.Nil(h.UnmarshalText([]byte("3.14")))
		t.Equal(h.ExposeSecret(), float32(3.14))
	})

	t.Run("float64_invalid", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float64]
		t.NotNil(h.UnmarshalText([]byte("not-a-float")))
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int]
		t.Nil(h.UnmarshalText([]byte("-7")))
		t.Equal(h.ExposeSecret(), -7)
	})

	t.Run("int_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int]
		t.NotNil(h.UnmarshalText([]byte("abc")))
	})

	t.Run("int8", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.Nil(h.UnmarshalText([]byte("-128")))
		t.Equal(h.ExposeSecret(), int8(-128))
	})

	t.Run("int8_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.NotNil(h.UnmarshalText([]byte("999")))
	})

	t.Run("int16", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int16]
		t.Nil(h.UnmarshalText([]byte("32767")))
		t.Equal(h.ExposeSecret(), int16(32767))
	})

	t.Run("int16_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int16]
		t.NotNil(h.UnmarshalText([]byte("99999")))
	})

	t.Run("int32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int32]
		t.Nil(h.UnmarshalText([]byte("-2147483648")))
		t.Equal(h.ExposeSecret(), int32(math.MinInt32))
	})

	t.Run("int32_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int32]
		t.NotNil(h.UnmarshalText([]byte("2147483648")))
	})

	t.Run("uint", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint]
		t.Nil(h.UnmarshalText([]byte("0")))
		t.Equal(h.ExposeSecret(), uint(0))
	})

	t.Run("uint_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint]
		t.NotNil(h.UnmarshalText([]byte("-1")))
	})

	t.Run("uint8", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint8]
		t.Nil(h.UnmarshalText([]byte("255")))
		t.Equal(h.ExposeSecret(), uint8(255))
	})

	t.Run("uint8_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint8]
		t.NotNil(h.UnmarshalText([]byte("256")))
	})

	t.Run("uint16", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint16]
		t.Nil(h.UnmarshalText([]byte("65535")))
		t.Equal(h.ExposeSecret(), uint16(65535))
	})

	t.Run("uint16_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint16]
		t.NotNil(h.UnmarshalText([]byte("65536")))
	})

	t.Run("uint32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint32]
		t.Nil(h.UnmarshalText([]byte("4294967295")))
		t.Equal(h.ExposeSecret(), uint32(math.MaxUint32))
	})

	t.Run("uint32_overflow", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint32]
		t.NotNil(h.UnmarshalText([]byte("4294967296")))
	})

	t.Run("float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float64]
		t.Nil(h.UnmarshalText([]byte("3.14")))
		t.Equal(h.ExposeSecret(), 3.14)
	})
}

func TestHandle_Scan(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string_from_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.Nil(h.Scan("token"))
		t.Equal(h.ExposeSecret(), "token")
	})

	t.Run("string_from_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.Nil(h.Scan([]byte("token")))
		t.Equal(h.ExposeSecret(), "token")
	})

	t.Run("bool_from_bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[bool]
		t.Nil(h.Scan(false))
		t.Equal(h.ExposeSecret(), false)
	})

	t.Run("bool_from_int64_zero", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[bool]
		t.Nil(h.Scan(int64(0)))
		t.Equal(h.ExposeSecret(), false)
	})

	t.Run("int64_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int64]
		t.Nil(h.Scan(int64(-99)))
		t.Equal(h.ExposeSecret(), int64(-99))
	})

	t.Run("float64_from_float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float64]
		t.Nil(h.Scan(float64(1.23)))
		t.Equal(h.ExposeSecret(), 1.23)
	})

	t.Run("nil_yields_zero", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.Nil(h.Scan("before"))
		t.Nil(h.Scan(nil))
		t.Equal(h.ExposeSecret(), "")
	})

	t.Run("type_mismatch_error", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		t.NotNil(h.Scan(int64(1)))
	})

	t.Run("int_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int]
		t.Nil(h.Scan(int64(42)))
		t.Equal(h.ExposeSecret(), 42)
	})

	t.Run("int8_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.Nil(h.Scan(int64(-128)))
		t.Equal(h.ExposeSecret(), int8(-128))
	})

	t.Run("int8_truncation", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.Nil(h.Scan(int64(300)))
		t.Equal(h.ExposeSecret(), int8(44)) // 300 wraps to 44 for int8
	})

	t.Run("int8_type_mismatch", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.NotNil(h.Scan("not-an-int64"))
	})

	t.Run("int16_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int16]
		t.Nil(h.Scan(int64(32767)))
		t.Equal(h.ExposeSecret(), int16(32767))
	})

	t.Run("int32_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int32]
		t.Nil(h.Scan(int64(math.MinInt32)))
		t.Equal(h.ExposeSecret(), int32(math.MinInt32))
	})

	t.Run("uint_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint]
		t.Nil(h.Scan(int64(0)))
		t.Equal(h.ExposeSecret(), uint(0))
	})

	t.Run("uint8_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint8]
		t.Nil(h.Scan(int64(255)))
		t.Equal(h.ExposeSecret(), uint8(255))
	})

	t.Run("uint8_truncation", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint8]
		t.Nil(h.Scan(int64(256)))
		t.Equal(h.ExposeSecret(), uint8(0)) // 256 wraps to 0 for uint8
	})

	t.Run("uint16_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint16]
		t.Nil(h.Scan(int64(65535)))
		t.Equal(h.ExposeSecret(), uint16(65535))
	})

	t.Run("uint32_from_int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[uint32]
		t.Nil(h.Scan(int64(math.MaxInt32)))
		t.Equal(h.ExposeSecret(), uint32(math.MaxInt32))
	})

	t.Run("float32_from_float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float32]
		t.Nil(h.Scan(float64(1.5)))
		t.Equal(h.ExposeSecret(), float32(1.5))
	})

	t.Run("float32_type_mismatch", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float32]
		t.NotNil(h.Scan("not-a-float64"))
	})

	t.Run("nil_yields_zero_numeric", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[int8]
		t.Nil(h.Scan(int64(42)))
		t.Nil(h.Scan(nil))
		t.Equal(h.ExposeSecret(), int8(0))
	})

	t.Run("no_panic_on_type_mismatch", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[float64]
		t.NotPanic(func() { _ = h.Scan("not-a-float") })
	})
}

// textUnmarshalerHandle verifies that Handle[T] satisfies encoding.TextUnmarshaler at compile time.
var _ encoding.TextUnmarshaler = (*sensitive.Handle[string])(nil)
