package sensitive_test

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/powerman/check"
	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

func TestSecretValuer_Value(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New("secret").ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value("secret"))
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New([]byte("raw")).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		b, ok := v.([]byte)
		t.True(ok, "Value should return []byte")
		t.Equal(string(b), "raw")
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New(true).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(true))
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New(42).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(42)))
	})

	t.Run("float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New(2.718).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(2.718))
	})

	t.Run("decimal_via_Valuer", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		d := decimal.NewFromFloat(1.5)
		sv := sensitive.New(d).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.NotNil(v, "decimal.Decimal.Value should return non-nil")
	})

	t.Run("unsupported_type_error_not_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New(testStruct{A: "x", B: 1}).ExposeSecretValuer()
		var err error
		t.NotPanic(func() { _, err = sv.Value() })
		t.NotNil(err)
	})

	t.Run("zero_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var r sensitive.Ref[string]
		v, err := r.ExposeSecretValuer().Value()
		t.Nil(err)
		t.Equal(v, driver.Value(""))
	})
}

func TestSecretValuer_redacts(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mysecretvalue"
	sv := sensitive.New(secret).ExposeSecretValuer()

	t.Run("fmt_verbs", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			t.NotContains(fmt.Sprintf(verb, sv), secret,
				"SecretValuer must not leak via %s", verb)
		}
	})
}

func TestSecretValuer_exposes(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mysecretvalue"

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New(secret).ExposeSecretValuer()
		b, err := json.Marshal(sv)
		t.Nil(err)
		t.Contains(string(b), secret, "SecretValuer must expose secret via json.Marshal")
	})

	t.Run("marshal_text", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		t.Run("string", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New("mytext").ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "mytext")
		})

		t.Run("bytes", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New([]byte("raw")).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "raw")
		})

		t.Run("bool", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New(true).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "true")
		})

		t.Run("int", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New(42).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "42")
		})

		t.Run("int8", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New(int8(-42)).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "-42")
		})

		t.Run("float64", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New(2.718).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "2.718")
		})

		t.Run("decimal_via_TextMarshaler", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			d := decimal.NewFromFloat(1.5)
			sv := sensitive.New(d).ExposeSecretValuer()
			text, err := sv.MarshalText()
			t.Nil(err)
			t.NotNil(text, "decimal.Decimal.MarshalText should return non-nil")
		})

		t.Run("unsupported_type_error_not_panic", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			sv := sensitive.New(testStruct{A: "x", B: 1}).ExposeSecretValuer()
			var err error
			t.NotPanic(func() { _, err = sv.MarshalText() })
			t.NotNil(err)
		})

		t.Run("zero_ref", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			var r sensitive.Ref[string]
			text, err := r.ExposeSecretValuer().MarshalText()
			t.Nil(err)
			t.Equal(string(text), "")
		})
	})
}

func TestSecretValuer_slog_redacts(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mysecretvalue"
	sv := sensitive.New(secret).ExposeSecretValuer()

	t.Run("json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, secret, "SecretValuer must not leak via slog JSONHandler")
		t.Contains(out, `"REDACTED"`, "SecretValuer must use type-preserving redacted value in slog JSONHandler")
	})

	t.Run("text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, secret, "SecretValuer must not leak via slog TextHandler")
		t.Contains(out, "REDACTED", "SecretValuer must use type-preserving redacted value in slog TextHandler")
	})

	t.Run("from_make_json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
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
		t := check.T(tt)
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
		t := check.T(tt)
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
		t := check.T(tt)
		sv := sensitive.New(42).ExposeSecretValuer()
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", sv)
		out := buf.String()
		t.NotContains(out, `valuer=42`, "int SecretValuer must not leak via slog TextHandler")
		t.Contains(out, "-2147483648", "int SecretValuer must return MinInt32 redacted via slog TextHandler")
	})
}

func TestHandleValuer_Value(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		hv := sensitive.Make("token").ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value("token"))
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		hv := sensitive.Make(true).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(true))
	})

	t.Run("int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		hv := sensitive.Make(int64(99)).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		t.Equal(v, driver.Value(int64(99)))
	})

	t.Run("float32_widens_to_float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		hv := sensitive.Make(float32(1.5)).ExposeSecretValuer()
		v, err := hv.Value()
		t.Nil(err)
		_, isFloat64 := v.(float64)
		t.True(isFloat64, "float32 should be widened to float64 for driver.Value")
	})

	t.Run("zero_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		v, err := h.ExposeSecretValuer().Value()
		t.Nil(err)
		t.Equal(v, driver.Value(""))
	})
}

func TestHandleValuer_redacts(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mytokenvalue"
	hv := sensitive.Make(secret).ExposeSecretValuer()

	t.Run("fmt_verbs", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			t.NotContains(fmt.Sprintf(verb, hv), secret,
				"HandleValuer must not leak via %s", verb)
		}
	})
}

func TestHandleValuer_exposes(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mytokenvalue"

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		hv := sensitive.Make(secret).ExposeSecretValuer()
		b, err := json.Marshal(hv)
		t.Nil(err)
		t.Contains(string(b), secret, "HandleValuer must expose secret via json.Marshal")
	})

	t.Run("marshal_text", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		t.Run("string", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			hv := sensitive.Make("token").ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "token")
		})

		t.Run("bool", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			hv := sensitive.Make(true).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "true")
		})

		t.Run("int", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			hv := sensitive.Make(42).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "42")
		})

		t.Run("float64", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			hv := sensitive.Make(3.14).ExposeSecretValuer()
			text, err := hv.MarshalText()
			t.Nil(err)
			t.Equal(string(text), "3.14")
		})

		t.Run("zero_handle", func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			var h sensitive.Handle[string]
			text, err := h.ExposeSecretValuer().MarshalText()
			t.Nil(err)
			t.Equal(string(text), "")
		})
	})
}

func TestSecretValuer_ToRef(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("from_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		const want = "secret"
		sv := sensitive.New(want).ExposeSecretValuer()
		got := sv.ToRef().ExposeSecret()
		t.Equal(got, want)
	})

	t.Run("from_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		const want = "token"
		sv := sensitive.Make(want).ExposeSecretValuer()
		got := sv.ToRef().ExposeSecret()
		t.Equal(got, want)
	})

	t.Run("zero_ref", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var r sensitive.Ref[string]
		sv := r.ExposeSecretValuer()
		t.Equal(sv.ToRef().ExposeSecret(), "")
	})

	t.Run("zero_handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var h sensitive.Handle[string]
		sv := h.ExposeSecretValuer()
		t.Equal(sv.ToRef().ExposeSecret(), "")
	})

	t.Run("not_secret", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		sv := sensitive.New("x").ExposeSecretValuer()
		_, ok := any(sv).(sensitive.Secret[string])
		t.False(ok, "SecretValuer must not implement Secret[T]")
	})
}

func TestSecretValuer_roundtrip(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("json", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
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
		t := check.T(tt)
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
		t := check.T(tt)
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
		t := check.T(tt)
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

func TestHandleValuer_slog_redacts(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	const secret = "mytokenvalue"
	hv := sensitive.Make(secret).ExposeSecretValuer()

	t.Run("json_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, secret, "HandleValuer must not leak via slog JSONHandler")
		t.Contains(out, `"REDACTED"`, "HandleValuer must use type-preserving redacted value in slog JSONHandler")
	})

	t.Run("text_handler", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		logger.Info("Test", "valuer", hv)
		out := buf.String()
		t.NotContains(out, secret, "HandleValuer must not leak via slog TextHandler")
		t.Contains(out, "REDACTED", "HandleValuer must use type-preserving redacted value in slog TextHandler")
	})
}
