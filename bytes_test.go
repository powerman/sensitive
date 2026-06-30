package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestBytesFormatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Bytes("value")
	var empty *sensitive.Bytes

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Bytes %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Bytes %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Bytes %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Bytes %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Bytes %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Bytes %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Bytes %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Bytes",
		},
		{
			name:       "Ptr Bytes %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bytes %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Bytes",
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

func TestBytesJSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Bytes("value")

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Bytes
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}

//nolint:paralleltest // Modifies global FormatBytesFn, so can't be parallel.
func TestBytesCustomFormatFn(tt *testing.T) {
	t := check.T(tt).MustAll()

	oldFn := sensitive.FormatBytesFn
	defer func() {
		sensitive.FormatBytesFn = oldFn
	}()
	sensitive.FormatBytesFn = func(_ sensitive.Bytes, f fmt.State, _ rune) {
		_, _ = f.Write([]byte("blah"))
	}

	value := sensitive.Bytes("value")
	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "\"YmxhaA==\"")
}

func BenchmarkBytes_Format(b *testing.B) {
	value := sensitive.Bytes("value")
	for range b.N {
		_ = fmt.Sprintf("%s", value)
	}
}

func BenchmarkBytes_FormatNative(b *testing.B) {
	value := "value"
	for range b.N {
		_ = value // Benchmark.
	}
}

func BenchmarkBytesJSON(b *testing.B) {
	value := sensitive.Bytes("value")
	for range b.N {
		_, _ = json.Marshal(value) //nolint:errchkjson // Benchmark, value is discarded.
	}
}

func BenchmarkBytes_JSONNative(b *testing.B) {
	value := "value"
	for range b.N {
		_, _ = json.Marshal(value)
	}
}
