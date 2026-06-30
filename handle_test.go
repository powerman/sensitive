package sensitive_test

import (
	"encoding/json"
	"fmt"
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
