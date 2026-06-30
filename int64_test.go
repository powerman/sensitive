package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestInt64_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int64(100)
	var empty *sensitive.Int64

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Int64 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Int64 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Int64 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Int64 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Int64 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Int64 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Int64 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Int64",
		},
		{
			name:       "Ptr Int64 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int64 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Int64",
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

func TestInt64_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Int64(42).ExposeSecret(), int64(42))
	t.Equal(sensitive.Int64(-1).ExposeSecret(), int64(-1))
}

func TestInt64_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int64(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestInt64_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int64(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Int64
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
