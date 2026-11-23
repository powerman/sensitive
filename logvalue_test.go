package sensitive_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/powerman/check"
	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

// logCase is a secret wrapped in every type which implements slog.LogValuer
// and the output expected from slog.JSONHandler and slog.TextHandler.
type logCase struct {
	name string
	vals []any
	json string
	text string
}

// both wraps v into every type which supports a Comparable T.
func both[T sensitive.Comparable](v T) []any {
	return []any{
		sensitive.New(v),
		sensitive.Make(v),
		sensitive.New(v).ExposeSecretValuer(),
		sensitive.Make(v).ExposeSecretValuer(),
	}
}

// refOnly wraps v into every type which supports any T.
func refOnly[T any](v T) []any {
	return []any{
		sensitive.New(v),
		sensitive.New(v).ExposeSecretValuer(),
	}
}

// logOutput returns what slog handlers print for the attribute "v".
func logOutput(v any) (jsonOut, textOut string) {
	opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
			return slog.Attr{}
		}
		return a
	}}
	var jb, tb bytes.Buffer
	slog.New(slog.NewJSONHandler(&jb, opts)).Info("m", "v", v)
	slog.New(slog.NewTextHandler(&tb, opts)).Info("m", "v", v)
	return strings.TrimSpace(jb.String()), strings.TrimSpace(tb.String())
}

func checkLogCases(tt *testing.T, cases []logCase) {
	tt.Helper()
	for _, tc := range cases {
		for _, v := range tc.vals {
			tt.Run(fmt.Sprintf("%s/%T", tc.name, v), func(tt *testing.T) {
				t := check.Must(tt)
				gotJSON, gotText := logOutput(v)
				t.Equal(gotJSON, `{"v":`+tc.json+`}`)
				t.Equal(gotText, "v="+tc.text)
				t.NotContains(gotJSON, "!ERROR")
				t.NotContains(gotText, "!ERROR")
			})
		}
	}
}

// setAllHooks makes every Format<Type>Fn print text as is.
func setAllHooks(text string) {
	hook := func(f fmt.State) { fmt.Fprint(f, text) }
	sensitive.FormatBoolFn = func(_ bool, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatBytesFn = func(_ []byte, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatDecimalFn = func(_ decimal.Decimal, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatFloat32Fn = func(_ float32, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatFloat64Fn = func(_ float64, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatIntFn = func(_ int, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatInt8Fn = func(_ int8, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatInt16Fn = func(_ int16, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatInt32Fn = func(_ int32, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatInt64Fn = func(_ int64, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatStringFn = func(_ string, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatUintFn = func(_ uint, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatUint8Fn = func(_ uint8, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatUint16Fn = func(_ uint16, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatUint32Fn = func(_ uint32, f fmt.State, _ rune) { hook(f) }
	sensitive.FormatUint64Fn = func(_ uint64, f fmt.State, _ rune) { hook(f) }
}

type unsupported struct{ A int }

//nolint:paralleltest // Modifies global Format<Type>Fn.
func TestLogValue_redact(t *testing.T) {
	sensitive.Redact()
	t.Cleanup(resetFormatFns)

	checkLogCases(t, []logCase{
		{"bool", both(true), `false`, `false`},
		{"string", both("s3cret"), `"REDACTED"`, `REDACTED`},
		{"int", both(-42), `123`, `123`},
		{"int8", both(int8(-42)), `123`, `123`},
		{"int16", both(int16(-42)), `123`, `123`},
		{"int32", both(int32(-42)), `123`, `123`},
		{"int64", both(int64(-42)), `123`, `123`},
		{"uint", both(uint(42)), `123`, `123`},
		{"uint8", both(uint8(42)), `123`, `123`},
		{"uint16", both(uint16(42)), `123`, `123`},
		{"uint32", both(uint32(42)), `123`, `123`},
		{"uint64", both(uint64(42)), `123`, `123`},
		{"float32", both(float32(0.5)), `123`, `123`},
		{"float64", both(0.5), `123`, `123`},
		{"bytes", refOnly([]byte("s3cret")), `"3vrO"`, `DEFACE`},
		{"decimal", refOnly(decimal.NewFromFloat(1.5)), `"123"`, `123`},
		{"unsupported", refOnly(unsupported{42}), `null`, `<nil>`},
	})
}

//nolint:paralleltest // Modifies global Format<Type>Fn and decimal.MarshalJSONWithoutQuotes.
func TestLogValue_decimalFollowsDecimalJSON(t *testing.T) {
	t.Cleanup(resetFormatFns)
	t.Cleanup(func() { decimal.MarshalJSONWithoutQuotes = false })

	for _, withoutQuotes := range []bool{false, true} {
		t.Run(fmt.Sprintf("withoutQuotes=%t", withoutQuotes), func(tt *testing.T) {
			t := check.Must(tt)
			decimal.MarshalJSONWithoutQuotes = withoutQuotes
			r := sensitive.New(decimal.NewFromFloat(1.5))
			want, err := json.Marshal(r)
			t.Nil(err)
			gotJSON, _ := logOutput(r)
			t.Equal(gotJSON, `{"v":`+string(want)+`}`)
		})
	}
}

func TestLogValue_disable(t *testing.T) {
	t.Setenv("GO_TEST_DISABLE_SENSITIVE", "1")
	sensitive.Disable()
	t.Cleanup(resetFormatFns)

	checkLogCases(t, []logCase{
		{"bool", both(true), `true`, `true`},
		{"string", both("s3cret"), `"s3cret"`, `s3cret`},
		{"int", both(-42), `-42`, `-42`},
		{"int8", both(int8(-42)), `-42`, `-42`},
		{"int16", both(int16(-42)), `-42`, `-42`},
		{"int32", both(int32(-42)), `-42`, `-42`},
		{"int64", both(int64(-42)), `-42`, `-42`},
		{"uint", both(uint(42)), `42`, `42`},
		{"uint8", both(uint8(42)), `42`, `42`},
		{"uint16", both(uint16(42)), `42`, `42`},
		{"uint32", both(uint32(42)), `42`, `42`},
		{"uint64", both(uint64(math.MaxUint64)), `18446744073709551615`, `18446744073709551615`},
		{"float32", both(float32(0.1)), `0.1`, `0.1`},
		{"float64", both(2.5), `2.5`, `2.5`},
		{"float32 NaN", both(float32(math.NaN())), `null`, `<nil>`},
		{"float32 +Inf", both(float32(math.Inf(1))), `null`, `<nil>`},
		{"float64 NaN", both(math.NaN()), `null`, `<nil>`},
		{"float64 -Inf", both(math.Inf(-1)), `null`, `<nil>`},
		{"bytes", refOnly([]byte("secret")), `"c2VjcmV0"`, `736563726574`},
		{"decimal", refOnly(decimal.NewFromFloat(42.42)), `"42.42"`, `42.42`},
		{"unsupported", refOnly(unsupported{42}), `null`, `<nil>`},
	})
}

//nolint:paralleltest // Modifies global Format<Type>Fn.
func TestLogValue_customLiteral(t *testing.T) {
	t.Cleanup(resetFormatFns)

	for _, tc := range []struct {
		logCase

		hook string
	}{
		{logCase{"bool", both(false), `true`, `true`}, "true"},
		{logCase{"int", both(1), `7`, `7`}, "7"},
		{logCase{"int8", both(int8(1)), `7`, `7`}, "7"},
		{logCase{"int64", both(int64(1)), `7`, `7`}, "7"},
		{logCase{"uint", both(uint(1)), `7`, `7`}, "7"},
		{logCase{"uint8", both(uint8(1)), `7`, `7`}, "7"},
		{logCase{"uint64", both(uint64(1)), `7`, `7`}, "7"},
		{logCase{"float32", both(float32(1)), `1.5`, `1.5`}, "1.5"},
		{logCase{"float64", both(float64(1)), `1.5`, `1.5`}, "1.5"},
		{logCase{"decimal", refOnly(decimal.NewFromInt(1)), `"1.5"`, `1.5`}, "1.5"},
		{logCase{"string", both("s3cret"), `"abc"`, `abc`}, "abc"},
	} {
		setAllHooks(tc.hook)
		checkLogCases(t, []logCase{tc.logCase})
	}
}

//nolint:paralleltest // Modifies global Format<Type>Fn.
func TestLogValue_customNotLiteral(t *testing.T) {
	t.Cleanup(resetFormatFns)

	for _, tc := range []struct {
		logCase

		hook string
	}{
		{logCase{"bool", both(true), `"***"`, `***`}, "***"},
		{logCase{"int", both(42), `"***"`, `***`}, "***"},
		{logCase{"uint64", both(uint64(42)), `"***"`, `***`}, "***"},
		{logCase{"float32", both(float32(42)), `"***"`, `***`}, "***"},
		{logCase{"float64", both(float64(42)), `"***"`, `***`}, "***"},
		{logCase{"decimal", refOnly(decimal.NewFromInt(42)), `"***"`, `***`}, "***"},
		{logCase{"uint8 out of range", both(uint8(42)), `"300"`, `300`}, "300"},
		{logCase{"int is not a float", both(42), `"1.5"`, `1.5`}, "1.5"},
		{logCase{"bytes", refOnly([]byte("s3cret")), `"Kioq"`, `2A2A2A`}, "***"},
	} {
		setAllHooks(tc.hook)
		checkLogCases(t, []logCase{tc.logCase})
	}
}

// resolvingHandler is a handler which renders values without fmt and marshalers:
// it resolves every attribute and keeps what is left for inspection.
type resolvingHandler struct {
	resolved *[]slog.Value
}

func (resolvingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h resolvingHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		*h.resolved = append(*h.resolved, a.Value.Resolve())
		return true
	})
	return nil
}

func (h resolvingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h resolvingHandler) WithGroup(string) slog.Handler      { return h }

// containsSecret walks v through pointers, interfaces, structs, slices and maps,
// including unexported fields, as a reflection-based dumper would do.
func containsSecret(v reflect.Value, secret string) bool {
	switch v.Kind() {
	case reflect.String:
		return strings.Contains(v.String(), secret)
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil() && containsSecret(v.Elem(), secret)
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range b {
				b[i] = byte(v.Index(i).Uint())
			}
			return bytes.Contains(b, []byte(secret))
		}
		for i := range v.Len() {
			if containsSecret(v.Index(i), secret) {
				return true
			}
		}
	case reflect.Struct:
		for _, f := range v.Fields() {
			if containsSecret(f, secret) {
				return true
			}
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			if containsSecret(it.Key(), secret) || containsSecret(it.Value(), secret) {
				return true
			}
		}
	}
	return false
}

func TestLogValue_resolvedHasNoSecret(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-value"

	t.Run("walker finds a secret", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		t.True(containsSecret(reflect.ValueOf(&struct{ a any }{secret}), secret))
		t.True(containsSecret(reflect.ValueOf(struct{ a []byte }{[]byte(secret)}), secret))
	})

	for _, v := range []any{
		sensitive.New(secret),
		sensitive.Make(secret),
		sensitive.New(secret).ExposeSecretValuer(),
		sensitive.New([]byte(secret)),
		sensitive.New([]byte(secret)).ExposeSecretValuer(),
		sensitive.New(unsupported{42}),
	} {
		t.Run(fmt.Sprintf("%T", v), func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			var resolved []slog.Value
			slog.New(resolvingHandler{&resolved}).Info("m", "v", v)
			t.Len(resolved, 1)
			got := resolved[0].Any()
			t.NotContains(fmt.Sprintf("%#v", got), secret)
			t.False(containsSecret(reflect.ValueOf(got), secret))
			_, isLogValuer := got.(slog.LogValuer)
			t.False(isLogValuer, "value must be fully resolved")
		})
	}
}

// FormatBytesFn is called with the verb 's' only, so the text form is the hex of its output
// whatever the hook does with the verb, and it is the same for slog and for MarshalText.
//
//nolint:paralleltest // Modifies global Format<Type>Fn.
func TestLogValue_bytesTextMatchesMarshalText(tt *testing.T) {
	tt.Cleanup(resetFormatFns)
	setAllHooks("***")
	t := check.Must(tt)

	r := sensitive.New([]byte("s3cret"))
	text, err := r.MarshalText()
	t.Nil(err)
	t.Equal(string(text), "2A2A2A")
	_, gotText := logOutput(r)
	t.Equal(gotText, "v="+string(text))
}
