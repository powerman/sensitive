package sensitive_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/powerman/check"
	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

func TestDecimalFormatting(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Decimal(decimal.NewFromFloat(100.1))
	var empty *sensitive.Decimal

	tests := []struct {
		name       string
		formatting string
		expected   string
		value      any
	}{
		{
			name:       "Decimal %s",
			formatting: "%s",
			value:      value,
		},
		{
			name:       "Decimal %q",
			formatting: "%q",
			value:      value,
		},
		{
			name:       "Decimal %v",
			formatting: "%v",
			value:      value,
		},
		{
			name:       "Decimal %#v",
			formatting: "%#v",
			value:      value,
		},
		{
			name:       "Decimal %x",
			formatting: "%x",
			value:      value,
		},
		{
			name:       "Decimal %X",
			formatting: "%X",
			value:      value,
		},
		{
			name:       "Decimal %T",
			formatting: "%T",
			value:      value,
			expected:   "sensitive.Decimal",
		},
		{
			name:       "Ptr Decimal %s",
			formatting: "%s",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %q",
			formatting: "%q",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %v",
			formatting: "%v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %#v",
			formatting: "%#v",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %x",
			formatting: "%x",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %X",
			formatting: "%X",
			value:      empty,
			expected:   "<nil>",
		},
		{
			name:       "Ptr Decimal %T",
			formatting: "%T",
			value:      empty,
			expected:   "*sensitive.Decimal",
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

func TestDecimal_MarshalText(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Decimal(decimal.NewFromFloat(100.1))

	b, err := value.MarshalText()
	t.Nil(err)
	t.Zero(string(b))
}

func TestDecimalJSON(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	value := sensitive.Decimal(decimal.NewFromFloat(100.1))

	b, err := json.Marshal(value)
	t.Nil(err)
	t.Equal(string(b), "null")

	var empty *sensitive.Decimal
	b, err = json.Marshal(empty)
	t.Nil(err)
	t.Equal(string(b), "null")
}
