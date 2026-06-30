package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestUint_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint(100)
	var empty *sensitive.Uint

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Uint %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Uint %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Uint %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Uint %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Uint %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Uint %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Uint %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Uint",
		},
		{
			name:       "Ptr Uint %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Uint",
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

func TestUint_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Uint(42).ExposeSecret(), uint(42))
	t.Equal(sensitive.Uint(0).ExposeSecret(), uint(0))
}

func TestUint_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestUint_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Uint
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
