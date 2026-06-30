package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestUint8_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint8(100)
	var empty *sensitive.Uint8

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Uint8 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Uint8 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Uint8 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Uint8 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Uint8 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Uint8 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Uint8 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Uint8",
		},
		{
			name:       "Ptr Uint8 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint8 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Uint8",
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

func TestUint8_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Uint8(42).ExposeSecret(), uint8(42))
	t.Equal(sensitive.Uint8(0).ExposeSecret(), uint8(0))
}

func TestUint8_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint8(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestUint8_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint8(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Uint8
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
