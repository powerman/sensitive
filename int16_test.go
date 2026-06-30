package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestInt16Formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int16(100)
	var empty *sensitive.Int16

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Int16 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Int16 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Int16 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Int16 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Int16 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Int16 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Int16 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Int16",
		},
		{
			name:       "Ptr Int16 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int16 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Int16",
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

func TestInt16_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int16(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestInt16JSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int16(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Int16
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
