package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestInt32_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int32(100)
	var empty *sensitive.Int32

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Int32 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Int32 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Int32 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Int32 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Int32 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Int32 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Int32 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Int32",
		},
		{
			name:       "Ptr Int32 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int32 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Int32",
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

func TestInt32_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Int32(42).ExposeSecret(), int32(42))
	t.Equal(sensitive.Int32(-1).ExposeSecret(), int32(-1))
}

func TestInt32_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int32(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestInt32_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int32(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Int32
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
