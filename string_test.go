package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestString_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.String("value")
	var empty *sensitive.String

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "String %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "String %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "String %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "String %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "String %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "String %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "String %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.String",
		},
		{
			name:       "Ptr String %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr String %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.String",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			result := fmt.Sprintf(tc.formatting, tc.value)
			t.Equal(result, tc.expected)
		})
	}
}

func TestString_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.String("value")

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "\"\"")

	var empty *sensitive.String
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}

func TestString_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.String("secret-string")
	t.Equal(value.ExposeSecret(), "secret-string")
	t.Equal(sensitive.String("").ExposeSecret(), "")
}

//nolint:paralleltest // Modifies global FormatStringFn, so can't be parallel.
func TestString_customFormatFn(tt *testing.T) {
	t := check.T(tt).MustAll()

	oldFn := sensitive.FormatStringFn
	defer func() {
		sensitive.FormatStringFn = oldFn
	}()
	sensitive.FormatStringFn = func(_ sensitive.String, f fmt.State, c rune) {
		sensitive.Format(f, c, "blah")
	}

	value := sensitive.String("value")
	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "\"blah\"")
}

func BenchmarkString_Format(b *testing.B) {
	value := sensitive.String("value")
	for range b.N {
		_ = fmt.Sprintf("%s", value)
	}
}

func BenchmarkString_FormatNative(b *testing.B) {
	value := "value"
	for range b.N {
		_ = value // Benchmark.
	}
}

func BenchmarkStringJSON(b *testing.B) {
	value := sensitive.String("value")
	for range b.N {
		_, _ = json.Marshal(value) //nolint:errchkjson // Benchmark, value is discarded.
	}
}

func BenchmarkString_JSONNative(b *testing.B) {
	value := "value"
	for range b.N {
		_, _ = json.Marshal(value)
	}
}
