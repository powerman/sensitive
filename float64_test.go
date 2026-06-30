package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestFloat64_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float64(100.1)
	var empty *sensitive.Float64

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Float64 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Float64 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Float64 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Float64 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Float64 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Float64 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Float64 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Float64",
		},
		{
			name:       "Ptr Float64 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float64 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Float64",
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

func TestFloat64_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Float64(2.71828).ExposeSecret(), 2.71828)
	t.Equal(sensitive.Float64(0).ExposeSecret(), 0.0)
}

func TestFloat64_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float64(100.1)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestFloat64_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float64(100.1)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Float64
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
