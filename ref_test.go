package sensitive_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

// testStruct is a user-defined struct used as a type parameter for Ref.
type testStruct struct {
	A string
	B int
}

// equal is a helper to compare two values with reflect.DeepEqual.
// It is not an assertion — it returns a bool.
func equal(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

// structWithUnexportedRef holds Ref values in unexported fields.
type structWithUnexportedRef struct {
	s  sensitive.Ref[string]
	bs sensitive.Ref[[]byte]
	st sensitive.Ref[testStruct]
}

// structWithInterfaceHoldingRef holds an interface containing a Ref
// in an unexported field, which is the scenario that defeats
// plain Bytes/String because fmt sees flagRO and skips Format.
type structWithInterfaceHoldingRef struct {
	v any
}

func TestRef_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := "my-secret"
	bSecret := sensitive.New(secret)

	tests := []struct {
		name       string
		formatting string
		value      any
		notWant    string
	}{
		{name: "Ref[string] %s", formatting: "%s", value: bSecret, notWant: secret},
		{name: "Ref[string] %q", formatting: "%q", value: bSecret, notWant: secret},
		{name: "Ref[string] %v", formatting: "%v", value: bSecret, notWant: secret},
		{name: "Ref[string] %+v", formatting: "%+v", value: bSecret, notWant: secret},
		{name: "Ref[string] %#v", formatting: "%#v", value: bSecret, notWant: secret},
		{name: "Ref[string] %x", formatting: "%x", value: bSecret, notWant: secret},
		{name: "Ref[string] %X", formatting: "%X", value: bSecret, notWant: secret},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			t.NotContains(fmt.Sprintf(tc.formatting, tc.value), tc.notWant)
		})
	}
}

func TestRef_reflectionSafety(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secretStr := "secret-value"
	secretBytes := []byte("secret-bytes")
	secretStruct := testStruct{A: "hidden", B: 42}

	parent := structWithUnexportedRef{
		s:  sensitive.New(secretStr),
		bs: sensitive.New(secretBytes),
		st: sensitive.New(secretStruct),
	}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}

	for _, verb := range verbs {
		t.Run("unexported_field_"+verb, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)

			result := fmt.Sprintf(verb, parent)

			t.NotContains(result, secretStr,
				"secret string should not appear in %s formatting", verb)
			t.NotContains(result, string(secretBytes),
				"secret bytes should not appear in %s formatting", verb)
			t.NotContains(result, secretStruct.A,
				"secret struct field A should not appear in %s formatting", verb)
		})
	}
}

func TestRef_interfaceInUnexportedField(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := "hidden-behind-interface"
	ref := sensitive.New(secret)

	parent := structWithInterfaceHoldingRef{
		v: ref,
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

func TestRef_deepEqual(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New("equal-value")
		b := sensitive.New("equal-value")
		t.True(equal(a, b), "DeepEqual Ref[string] with same value")
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New([]byte("equal-bytes"))
		b := sensitive.New([]byte("equal-bytes"))
		t.True(equal(a, b), "DeepEqual Ref[[]byte] with same value")
	})

	t.Run("struct", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New(testStruct{A: "x", B: 1})
		b := sensitive.New(testStruct{A: "x", B: 1})
		t.True(equal(a, b), "DeepEqual Ref[testStruct] with same value")
	})

	t.Run("different", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New("alpha")
		b := sensitive.New("beta")
		t.False(equal(a, b), "DeepEqual Ref[string] with different values")
	})
}

func TestRef_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("round_trip", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		expected := "sensitive-data"
		b := sensitive.New(expected)
		t.Equal(b.ExposeSecret(), expected)
	})

	t.Run("zero_value_safe", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var z sensitive.Ref[string]
		t.NotPanic(func() { _ = z.ExposeSecret() },
			"zero value Ref must not panic on ExposeSecret")
		t.Equal(z.ExposeSecret(), "")
	})

	t.Run("primitive_types", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		t.Equal(sensitive.New(42).ExposeSecret(), 42)
		t.Equal(sensitive.New(3.14).ExposeSecret(), 3.14)
		t.Equal(sensitive.New(true).ExposeSecret(), true)
	})
}

func TestRef_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.New("my-json-value")

	result, err := json.Marshal(value)
	t.Nil(err)
	t.NotContains(string(result), "my-json-value")

	var empty *sensitive.Ref[string]
	result, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(result), "null")
}

func TestRef_zeroValue(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("format_no_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		t.NotPanic(func() {
			_ = fmt.Sprintf("%v", sensitive.Ref[string]{})
		})
	})

	t.Run("expose_secret_no_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		t.NotPanic(func() {
			_ = sensitive.Ref[string]{}.ExposeSecret()
		})
	})
}

// --- Redact and Disable tests via subprocess ---

// testRefGlobalMode exercises Ref formatting under a specific
// global mode (default, Redact, or Disable).
// It is invoked as a subprocess entry point, so os.Exit is acceptable.
//
//nolint:revive // deep-exit: called from subprocess entry point.
func testRefGlobalMode(mode string) {
	switch mode {
	case "Redact":
		sensitive.Redact()
	case "Disable":
		sensitive.Disable()
	}

	checkFormat := func(want string, b any) {
		got := fmt.Sprintf("%v", b)
		if got != want {
			fmt.Fprintf(os.Stderr, "FAIL: got %q, want %q\n", got, want)
			os.Exit(1)
		}
	}

	switch mode {
	case "default":
		// Default Format<Type>Fn are no-ops → empty output.
		checkFormat("", sensitive.New("str"))
		checkFormat("", sensitive.New(42))
		checkFormat("", sensitive.New([]byte("bytes")))
	case "Redact":
		// Redact sets typed redacted values.
		checkFormat("REDACTED", sensitive.New("str"))
		checkFormat(fmt.Sprintf("%v", math.MinInt32), sensitive.New(42))
		checkFormat("[222 250 206]", sensitive.New([]byte("bytes")))
	case "Disable":
		// Disable shows real values.
		checkFormat("str", sensitive.New("str"))
	}

	os.Exit(0)
}

func TestRef_defaultMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runRefSubprocess(t, "default")
}

func TestRef_redactMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runRefSubprocess(t, "Redact")
}

func TestRef_disableMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runRefSubprocess(t, "Disable")
}

// runRefSubprocess re-runs this test binary with a special marker
// to execute testRefGlobalMode with the given mode.
func runRefSubprocess(t *check.C, mode string) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestRef_globalModeHelper$",
	)
	cmd.Env = append(os.Environ(),
		"_REF_MODE="+mode,
		"GO_TEST_DISABLE_SENSITIVE=1", // Always set; only used in Disable mode.
	)
	out, err := cmd.CombinedOutput()
	t.Nil(err, "subprocess for mode %s must exit successfully:\n%s", mode, out)
}

// testRef_globalModeHelper is a Test function that acts as an entry
// point for the subprocess call in runRefSubprocess. It reads the
// mode from env and delegates to testRefGlobalMode.
func TestRef_globalModeHelper(tt *testing.T) {
	tt.Parallel()

	mode := os.Getenv("_REF_MODE")
	if mode == "" {
		tt.Skip("not running in subprocess")
	}
	testRefGlobalMode(mode)
}
