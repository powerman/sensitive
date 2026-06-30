package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestFloat32_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float32(100.1)
	var empty *sensitive.Float32

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Float32 %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Float32 %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Float32 %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Float32 %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Float32 %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Float32 %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Float32 %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Float32",
		},
		{
			name:       "Ptr Float32 %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Float32 %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Float32",
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

func TestFloat32_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Float32(3.14).ExposeSecret(), float32(3.14))
	t.Equal(sensitive.Float32(0).ExposeSecret(), float32(0))
}

func TestFloat32_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float32(100.1)

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestFloat32_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Float32(100.1)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Float32
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
