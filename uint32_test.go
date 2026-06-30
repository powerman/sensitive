package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestUint32Formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint32(100)
	var empty *sensitive.Uint32

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Uint32 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Uint32 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Uint32 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Uint32 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Uint32 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Uint32 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Uint32 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Uint32",
		},
		{
			name:       "Ptr Uint32 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint32 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Uint32",
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

func TestUint32_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint32(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestUint32JSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint32(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Uint32
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
