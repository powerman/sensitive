package sensitive_test

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"testing"

	"github.com/powerman/check"
	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

func TestSecretValuer_Value(t *testing.T) {
	t.Parallel()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New("secret").ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value("secret"))
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New([]byte("raw")).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		b, ok := v.([]byte)
		t.True(ok, "Value should return []byte")
		t.Equal(string(b), "raw")
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(true).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(true))
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(42).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(42)))
	})

	t.Run("float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(2.718).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(2.718))
	})

	t.Run("decimal_via_Valuer", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		d := decimal.NewFromFloat(1.5)
		sv := sensitive.New(d).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.NotNil(v, "decimal.Decimal.Value should return non-nil")
	})

	t.Run("unsupported_type_error_not_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(testStruct{A: "x", B: 1}).ExposeSecretValuer()
		var err error
		t.NotPanic(func() { _, err = sv.Value() })
		t.NotNil(err)
	})

	t.Run("zero_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var r sensitive.Ref[string]
		v, err := r.ExposeSecretValuer().Value()
		t.Nil(err)
		t.Equal(v, driver.Value(""))
	})

	t.Run("int8", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(int8(-128)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(-128)))
	})

	t.Run("int16", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(int16(32767)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(32767)))
	})

	t.Run("int32", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(int32(math.MinInt32)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(math.MinInt32)))
	})

	t.Run("int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(int64(math.MinInt64)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(math.MinInt64)))
	})

	t.Run("uint", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(uint(0)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(0)))
	})

	t.Run("uint8", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(uint8(255)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(255)))
	})

	t.Run("uint16", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(uint16(65535)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(65535)))
	})

	t.Run("uint32", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(uint32(math.MaxUint32)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(math.MaxUint32)))
	})

	t.Run("float32", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(float32(1.5)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		_, isFloat64 := v.(float64)
		t.True(isFloat64, "float32 should be widened to float64 for driver.Value")
	})
}

func TestSecretValuer_redacts(t *testing.T) {
	t.Parallel()

	const secret = "mysecretvalue"
	sv := sensitive.New(secret).ExposeSecretValuer()

	t.Run("fmt_verbs", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			t.NotContains(fmt.Sprintf(verb, sv), secret,
				"SecretValuer must not leak via %s", verb)
		}
	})
}

func TestSecretValuer_exposes(t *testing.T) {
	t.Parallel()

	const secret = "mysecretvalue"

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(secret).ExposeSecretValuer()
		b, err := json.Marshal(sv)
		t.Nil(err)
		t.Contains(string(b), secret, "SecretValuer must expose secret via json.Marshal")
	})

	t.Run("marshal_text", func(t *testing.T) {
		t.Parallel()

		t.Run("string", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New("mytext").ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "mytext")
		})

		t.Run("bytes", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New([]byte("raw")).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "raw")
		})

		t.Run("bool", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(true).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "true")
		})

		t.Run("int", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(42).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "42")
		})

		t.Run("int8", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(int8(-42)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "-42")
		})

		t.Run("int16", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(int16(32767)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "32767")
		})

		t.Run("int32", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(int32(math.MinInt32)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "-2147483648")
		})

		t.Run("int64", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(int64(-1)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "-1")
		})

		t.Run("uint", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(uint(0)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "0")
		})

		t.Run("uint8", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(uint8(255)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "255")
		})

		t.Run("uint16", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(uint16(65535)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "65535")
		})

		t.Run("uint32", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(uint32(math.MaxUint32)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "4294967295")
		})

		t.Run("float32", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(float32(1.5)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "1.5")
		})

		t.Run("float64", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(2.718).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "2.718")
		})

		t.Run("decimal_via_TextMarshaler", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			d := decimal.NewFromFloat(1.5)
			sv := sensitive.New(d).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.NotNil(text, "decimal.Decimal.MarshalText should return non-nil")
		})

		t.Run("unsupported_type_error_not_panic", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			sv := sensitive.New(testStruct{A: "x", B: 1}).ExposeSecretValuer()
			var err error
			t.NotPanic(func() { _, err = sv.MarshalText() })
			t.NotNil(err)
		})

		t.Run("zero_ref", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			var r sensitive.Ref[string]
			text, err := r.ExposeSecretValuer().MarshalText()
			t.Nil(err)
			t.Equal(string(text), "")
		})
	})
}

func TestSecretValuer_slog_redacts(t *testing.T) {
	t.Parallel()

	const secret = "mysecretvalue"
	sv := sensitive.New(secret).ExposeSecretValuer()

	t.Run("json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, secret, "SecretValuer must not leak via slog JSONHandler")
		t.Contains(out, `"REDACTED"`, "SecretValuer must use type-preserving redacted value in slog JSONHandler")
	})

	t.Run("text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, secret, "SecretValuer must not leak via slog TextHandler")
		t.Contains(out, "REDACTED", "SecretValuer must use type-preserving redacted value in slog TextHandler")
	})

	t.Run("from_make_json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const token = "s3cr3t-t0k3n"
		hv := sensitive.Make(token).ExposeSecretValuer()
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, token, "HandleValuer must not leak via slog JSONHandler")
		t.Contains(out, `"REDACTED"`, "HandleValuer must use type-preserving redacted value in slog JSONHandler")
	})

	t.Run("from_make_text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const token = "s3cr3t-t0k3n"
		hv := sensitive.Make(token).ExposeSecretValuer()
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, token, "HandleValuer must not leak via slog TextHandler")
		t.Contains(out, "REDACTED", "HandleValuer must use type-preserving redacted value in slog TextHandler")
	})

	t.Run("int_json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(42).ExposeSecretValuer()
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, `"valuer":42`, "int SecretValuer must not leak via slog JSONHandler")
		t.Contains(out, "-2147483648", "int SecretValuer must return MinInt32 redacted via slog JSONHandler")
	})

	t.Run("int_text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(42).ExposeSecretValuer()
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, `valuer=42`, "int SecretValuer must not leak via slog TextHandler")
		t.Contains(out, "-2147483648", "int SecretValuer must return MinInt32 redacted via slog TextHandler")
	})
}

func TestHandleValuer_Value(t *testing.T) {
	t.Parallel()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		hv := sensitive.Make("token").ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value("token"))
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		hv := sensitive.Make(true).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(true))
	})

	t.Run("int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		hv := sensitive.Make(int64(99)).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(99)))
	})

	t.Run("float32_widens_to_float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		hv := sensitive.Make(float32(1.5)).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		_, isFloat64 := v.(float64)
		t.True(isFloat64, "float32 should be widened to float64 for driver.Value")
	})

	t.Run("zero_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var h sensitive.Handle[string]
		v, err := h.ExposeSecretValuer().Value()
		t.Nil(err)
		t.Equal(v, driver.Value(""))
	})
}

func TestHandleValuer_redacts(t *testing.T) {
	t.Parallel()

	const secret = "mytokenvalue"
	hv := sensitive.Make(secret).ExposeSecretValuer()

	t.Run("fmt_verbs", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			t.NotContains(fmt.Sprintf(verb, hv), secret,
				"HandleValuer must not leak via %s", verb)
		}
	})
}

func TestHandleValuer_exposes(t *testing.T) {
	t.Parallel()

	const secret = "mytokenvalue"

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		hv := sensitive.Make(secret).ExposeSecretValuer()
		b, err := json.Marshal(hv)
		t.Nil(err)
		t.Contains(string(b), secret, "HandleValuer must expose secret via json.Marshal")
	})

	t.Run("marshal_text", func(t *testing.T) {
		t.Parallel()

		t.Run("string", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			hv := sensitive.Make("token").ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "token")
		})

		t.Run("bool", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			hv := sensitive.Make(true).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "true")
		})

		t.Run("int", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			hv := sensitive.Make(42).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "42")
		})

		t.Run("float64", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			hv := sensitive.Make(3.14).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "3.14")
		})

		t.Run("zero_handle", func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			var h sensitive.Handle[string]
			text, err := h.ExposeSecretValuer().MarshalText()
			t.Nil(err)
			t.Equal(string(text), "")
		})
	})
}

func TestSecretValuer_ToRef(t *testing.T) {
	t.Parallel()

	t.Run("from_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const want = "secret"
		sv := sensitive.New(want).ExposeSecretValuer()
		got := sv.ToRef().ExposeSecret()
		t.Equal(got, want)
	})

	t.Run("from_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const want = "token"
		sv := sensitive.Make(want).ExposeSecretValuer()
		got := sv.ToRef().ExposeSecret()
		t.Equal(got, want)
	})

	t.Run("zero_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var r sensitive.Ref[string]
		sv := r.ExposeSecretValuer()
		t.Equal(sv.ToRef().ExposeSecret(), "")
	})

	t.Run("zero_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var h sensitive.Handle[string]
		sv := h.ExposeSecretValuer()
		t.Equal(sv.ToRef().ExposeSecret(), "")
	})

	t.Run("not_secret", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New("x").ExposeSecretValuer()
		_, ok := any(sv).(sensitive.Secret[string])
		t.False(ok, "SecretValuer must not implement Secret[T]")
	})
}

func TestSecretValuer_roundtrip(t *testing.T) {
	t.Parallel()

	t.Run("json", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New("roundtrip-secret").ExposeSecretValuer()
		b, err := json.Marshal(sv)
		t.Nil(err)

		var got sensitive.SecretValuer[string]
		err = json.Unmarshal(b, &got)
		t.Nil(err)
		t.Equal(got.ToRef().ExposeSecret(), "roundtrip-secret")
	})

	t.Run("text", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New("text-roundtrip").ExposeSecretValuer()
		b, err := sv.MarshalText()
		t.Nil(err)

		var got sensitive.SecretValuer[string]
		err = got.UnmarshalText(b)
		t.Nil(err)
		t.Equal(got.ToRef().ExposeSecret(), "text-roundtrip")
	})

	t.Run("after_ingest_redacts_fmt", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const secret = "ingested-secret"
		b, err := json.Marshal(sensitive.New(secret).ExposeSecretValuer())
		t.Nil(err)

		var sv sensitive.SecretValuer[string]
		t.Nil(json.Unmarshal(b, &sv))
		t.NotContains(fmt.Sprintf("%v", sv), secret,
			"SecretValuer must redact under fmt after ingest")
	})

	t.Run("after_ingest_redacts_slog", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		const secret = "ingested-slog-secret"
		b, err := json.Marshal(sensitive.New(secret).ExposeSecretValuer())
		t.Nil(err)

		var sv sensitive.SecretValuer[string]
		t.Nil(json.Unmarshal(b, &sv))

		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, secret, "SecretValuer must redact under slog after ingest")
	})
}

func TestHandleValuer_slog_redacts(t *testing.T) {
	t.Parallel()

	const secret = "mytokenvalue"
	hv := sensitive.Make(secret).ExposeSecretValuer()

	t.Run("json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, secret, "HandleValuer must not leak via slog JSONHandler")
		t.Contains(out, `"REDACTED"`, "HandleValuer must use type-preserving redacted value in slog JSONHandler")
	})

	t.Run("text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, secret, "HandleValuer must not leak via slog TextHandler")
		t.Contains(out, "REDACTED", "HandleValuer must use type-preserving redacted value in slog TextHandler")
	})
}

func TestSecretValuer_slog_perTypeSentinels(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		valuer   slog.LogValuer
		secret   string
		sentinel string
	}

	tests := []testCase{
		{
			name:     "bool",
			valuer:   sensitive.New(true).ExposeSecretValuer(),
			secret:   "true",
			sentinel: `false`, // LogValue returns slog.BoolValue(false)
		},
		{
			name:     "string",
			valuer:   sensitive.New("my-secret").ExposeSecretValuer(),
			secret:   "my-secret",
			sentinel: `REDACTED`,
		},
		{
			name:     "bytes",
			valuer:   sensitive.New([]byte("secret-bytes")).ExposeSecretValuer(),
			secret:   "secret-bytes",
			sentinel: "3vrO", // base64 of []byte{0xDE, 0xFA, 0xCE}
		},
		{
			name:     "int",
			valuer:   sensitive.New(42).ExposeSecretValuer(),
			secret:   `"valuer":42`,
			sentinel: "-2147483648", // math.MinInt32
		},
		{
			name:     "int8",
			valuer:   sensitive.New(int8(-100)).ExposeSecretValuer(),
			secret:   `"valuer":-100`,
			sentinel: "-128", // math.MinInt8
		},
		{
			name:     "int16",
			valuer:   sensitive.New(int16(-30000)).ExposeSecretValuer(),
			secret:   `"valuer":-30000`,
			sentinel: "-32768", // math.MinInt16
		},
		{
			name:     "int32",
			valuer:   sensitive.New(int32(-20000000)).ExposeSecretValuer(),
			secret:   `"valuer":-20000000`,
			sentinel: "-2147483648", // math.MinInt32
		},
		{
			name:     "int64",
			valuer:   sensitive.New(int64(-1)).ExposeSecretValuer(),
			secret:   `"valuer":-1`,
			sentinel: "-9223372036854775808", // math.MinInt64
		},
		{
			name:     "uint",
			valuer:   sensitive.New(uint(100)).ExposeSecretValuer(),
			secret:   `"valuer":100`,
			sentinel: "4294967295", // math.MaxUint32
		},
		{
			name:     "uint8",
			valuer:   sensitive.New(uint8(100)).ExposeSecretValuer(),
			secret:   `"valuer":100`,
			sentinel: "255", // math.MaxUint8
		},
		{
			name:     "uint16",
			valuer:   sensitive.New(uint16(1000)).ExposeSecretValuer(),
			secret:   `"valuer":1000`,
			sentinel: "65535", // math.MaxUint16
		},
		{
			name:     "uint32",
			valuer:   sensitive.New(uint32(100000)).ExposeSecretValuer(),
			secret:   `"valuer":100000`,
			sentinel: "4294967295", // math.MaxUint32
		},
		{
			name:     "uint64",
			valuer:   sensitive.New(uint64(100)).ExposeSecretValuer(),
			secret:   `"valuer":100`,
			sentinel: "18446744073709551615", // math.MaxUint64
		},
		{
			name:     "float32",
			valuer:   sensitive.New(float32(1.5)).ExposeSecretValuer(),
			secret:   `"valuer":1.5`,
			sentinel: "NaN", // LogValue returns NaN for float32
		},
		{
			name:     "float64",
			valuer:   sensitive.New(2.718).ExposeSecretValuer(),
			secret:   `"valuer":2.718`,
			sentinel: "NaN", // LogValue returns NaN for float64
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)

			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			logger.Info("Test", "valuer", tc.valuer)
			out := buf.String()

			t.NotContains(out, tc.secret, "SecretValuer must not leak the secret via slog JSONHandler for %s", tc.name)
			t.Contains(out, tc.sentinel, "SecretValuer LogValue must return type-specific sentinel for %s", tc.name)
		})
	}
}

func TestSecretValuer_IsZero(t *testing.T) {
	t.Parallel()

	t.Run("zero_string_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var r sensitive.Ref[string]
		t.True(r.ExposeSecretValuer().IsZero(), "zero Ref must produce zero SecretValuer")
	})

	t.Run("zero_string_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var h sensitive.Handle[string]
		t.True(h.ExposeSecretValuer().IsZero(), "zero Handle must produce zero SecretValuer")
	})

	t.Run("non_zero_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		r := sensitive.New("hello")
		t.False(r.ExposeSecretValuer().IsZero(), "non-zero SecretValuer must return false for IsZero")
	})

	t.Run("zero_int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		r := sensitive.New(0)
		t.True(r.ExposeSecretValuer().IsZero(), "SecretValuer with zero int must return true for IsZero")
	})

	t.Run("non_zero_int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		r := sensitive.New(42)
		t.False(r.ExposeSecretValuer().IsZero(), "SecretValuer with non-zero int must return false for IsZero")
	})
}

func TestSecretValuer_Scan(t *testing.T) {
	t.Parallel()

	t.Run("round_trip_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var sv sensitive.SecretValuer[string]
		t.Nil(sv.Scan("scanned-secret"))
		t.Equal(sv.ToRef().ExposeSecret(), "scanned-secret")
	})

	t.Run("nil_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var sv sensitive.SecretValuer[string]
		t.Nil(sv.Scan("before"))
		t.Nil(sv.Scan(nil))
		t.Equal(sv.ToRef().ExposeSecret(), "")
	})

	t.Run("round_trip_int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var sv sensitive.SecretValuer[int]
		t.Nil(sv.Scan(int64(42)))
		t.Equal(sv.ToRef().ExposeSecret(), 42)
	})
}
