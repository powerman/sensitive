package sensitive_test

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
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

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		b, err := json.Marshal(sv)
		t.Nil(err)
		t.NotContains(string(b), secret, "SecretValuer must not leak via json.Marshal")
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

	t.Run("json_marshal", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		b, err := json.Marshal(hv)
		t.Nil(err)
		t.NotContains(string(b), secret, "HandleValuer must not leak via json.Marshal")
	})
}
