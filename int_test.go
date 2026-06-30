package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestIntFormatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int(100)
	var empty *sensitive.Int

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Int %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Int %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Int %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Int %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Int %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Int %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Int %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Int",
		},
		{
			name:       "Ptr Int %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Int %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Int",
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

func TestInt_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestIntJSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Int(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Int
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
