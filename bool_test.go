package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestBool_formatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Bool(true)
	var empty *sensitive.Bool

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Bool %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Bool %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Bool %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Bool %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Bool %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Bool %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Bool %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Bool",
		},
		{
			name:       "Ptr Bool %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Bool %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Bool",
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

func TestBool_json(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Bool(true)

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Bool
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}

func TestBool_ExposeSecret(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Equal(sensitive.Bool(true).ExposeSecret(), true)
	t.Equal(sensitive.Bool(false).ExposeSecret(), false)
}

//nolint:paralleltest // Modifies global FormatBoolFn, so can't be parallel.
func TestBool_customFormatFn(tt *testing.T) {
	t := check.T(tt).MustAll()

	oldFn := sensitive.FormatBoolFn
	defer func() {
		sensitive.FormatBoolFn = oldFn
	}()
	sensitive.FormatBoolFn = func(_ sensitive.Bool, f fmt.State, _ rune) {
		_, _ = f.Write([]byte("blah"))
	}

	value := sensitive.Bool(true)
	t.Equal(fmt.Sprintf("%s", value), "blah")
}
