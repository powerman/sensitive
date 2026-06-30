package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestInt8Formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int8(100)
	var empty *sensitive.Int8

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Int8 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Int8 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Int8 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Int8 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Int8 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Int8 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Int8 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Int8",
		},
		{
			name:       "Ptr Int8 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int8 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Int8",
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

func TestInt8_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int8(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestInt8JSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int8(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Int8
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
