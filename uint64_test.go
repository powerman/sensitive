package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestUint64_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint64(100)
	var empty *sensitive.Uint64

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Uint64 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Uint64 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Uint64 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Uint64 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Uint64 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Uint64 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Uint64 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Uint64",
		},
		{
			name:       "Ptr Uint64 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Uint64 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Uint64",
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

func TestUint64_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Uint64(42).ExposeSecret(), uint64(42))
	t.Equal(sensitive.Uint64(0).ExposeSecret(), uint64(0))
}

func TestUint64_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint64(100)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestUint64_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Uint64(100)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Uint64
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
