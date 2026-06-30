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

// testStruct is a user-defined struct used as a type parameter for Boxed.
type testStruct struct {
	A string
	B int
}

// equal is a helper to compare two values with reflect.DeepEqual.
// It is not an assertion — it returns a bool.
func equal(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

// structWithUnexportedBoxed holds Boxed values in unexported fields.
type structWithUnexportedBoxed struct {
	s  sensitive.Boxed[string]
	bs sensitive.Boxed[[]byte]
	st sensitive.Boxed[testStruct]
}

// structWithInterfaceHoldingBoxed holds an interface containing a Boxed
// in an unexported field, which is the scenario that defeats
// plain Bytes/String because fmt sees flagRO and skips Format.
type structWithInterfaceHoldingBoxed struct {
	v any
}

func TestBoxed_formatting(tt *testing.T) {
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
		{name: "Boxed[string] %s", formatting: "%s", value: bSecret, notWant: secret},
		{name: "Boxed[string] %q", formatting: "%q", value: bSecret, notWant: secret},
		{name: "Boxed[string] %v", formatting: "%v", value: bSecret, notWant: secret},
		{name: "Boxed[string] %+v", formatting: "%+v", value: bSecret, notWant: secret},
		{name: "Boxed[string] %#v", formatting: "%#v", value: bSecret, notWant: secret},
		{name: "Boxed[string] %x", formatting: "%x", value: bSecret, notWant: secret},
		{name: "Boxed[string] %X", formatting: "%X", value: bSecret, notWant: secret},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			t.NotContains(fmt.Sprintf(tc.formatting, tc.value), tc.notWant)
		})
	}
}

func TestBoxed_reflectionSafety(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secretStr := "secret-value"
	secretBytes := []byte("secret-bytes")
	secretStruct := testStruct{A: "hidden", B: 42}

	parent := structWithUnexportedBoxed{
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

func TestBoxed_interfaceInUnexportedField(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := "hidden-behind-interface"
	boxed := sensitive.New(secret)

	parent := structWithInterfaceHoldingBoxed{
		v: boxed,
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

func TestBoxed_comparable(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	// Compile-time check: Boxed[T] must be usable as a map key.
	var _ map[sensitive.Boxed[string]]struct{}

	a := sensitive.New("hello")
	b := sensitive.New("hello")

	m := map[sensitive.Boxed[string]]int{
		a: 1,
		b: 2,
	}
	t.Len(m, 2, "each New call produces a unique map key")
	t.Equal(m[a], 1)
	t.Equal(m[b], 2)
}

func TestBoxed_deepEqual(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New("equal-value")
		b := sensitive.New("equal-value")
		t.True(equal(a, b), "DeepEqual Boxed[string] with same value")
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New([]byte("equal-bytes"))
		b := sensitive.New([]byte("equal-bytes"))
		t.True(equal(a, b), "DeepEqual Boxed[[]byte] with same value")
	})

	t.Run("struct", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New(testStruct{A: "x", B: 1})
		b := sensitive.New(testStruct{A: "x", B: 1})
		t.True(equal(a, b), "DeepEqual Boxed[testStruct] with same value")
	})

	t.Run("different", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := sensitive.New("alpha")
		b := sensitive.New("beta")
		t.False(equal(a, b), "DeepEqual Boxed[string] with different values")
	})
}

func TestBoxed_ExposeSecret(tt *testing.T) {
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

		var z sensitive.Boxed[string]
		t.NotPanic(func() { _ = z.ExposeSecret() },
			"zero value Boxed must not panic on ExposeSecret")
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

func TestBoxed_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.New("my-json-value")

	result, err := json.Marshal(value)
	t.Nil(err)
	t.NotContains(string(result), "my-json-value")

	var empty *sensitive.Boxed[string]
	result, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(result), "null")
}

func TestBoxed_zeroValue(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("format_no_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		t.NotPanic(func() {
			_ = fmt.Sprintf("%v", sensitive.Boxed[string]{})
		})
	})

	t.Run("expose_secret_no_panic", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		t.NotPanic(func() {
			_ = sensitive.Boxed[string]{}.ExposeSecret()
		})
	})
}

// --- Redact and Disable tests via subprocess ---

// testBoxedGlobalMode exercises Boxed formatting under a specific
// global mode (default, Redact, or Disable).
// It is invoked as a subprocess entry point, so os.Exit is acceptable.
//
//nolint:revive // deep-exit: called from subprocess entry point.
func testBoxedGlobalMode(mode string) {
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

func TestBoxed_defaultMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runBoxedSubprocess(t, "default")
}

func TestBoxed_redactMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runBoxedSubprocess(t, "Redact")
}

func TestBoxed_disableMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runBoxedSubprocess(t, "Disable")
}

// runBoxedSubprocess re-runs this test binary with a special marker
// to execute testBoxedGlobalMode with the given mode.
func runBoxedSubprocess(t *check.C, mode string) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestBoxed_globalModeHelper$",
	)
	cmd.Env = append(os.Environ(),
		"_BOXED_MODE="+mode,
		"GO_TEST_DISABLE_SENSITIVE=1", // Always set; only used in Disable mode.
	)
	out, err := cmd.CombinedOutput()
	t.Nil(err, "subprocess for mode %s must exit successfully:\n%s", mode, out)
}

// testBoxed_globalModeHelper is a Test function that acts as an entry
// point for the subprocess call in runBoxedSubprocess. It reads the
// mode from env and delegates to testBoxedGlobalMode.
func TestBoxed_globalModeHelper(tt *testing.T) {
	tt.Parallel()

	mode := os.Getenv("_BOXED_MODE")
	if mode == "" {
		tt.Skip("not running in subprocess")
	}
	testBoxedGlobalMode(mode)
}
