package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestUint16_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint16(100)
	var empty *sensitive.Uint16

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Uint16 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Uint16 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Uint16 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Uint16 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Uint16 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Uint16 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Uint16 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Uint16",
		},
		{
			name:       "Ptr Uint16 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint16 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Uint16",
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

func TestUint16_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Uint16(42).ExposeSecret(), uint16(42))
	t.Equal(sensitive.Uint16(0).ExposeSecret(), uint16(0))
}

func TestUint16_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint16(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestUint16_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint16(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Uint16
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
