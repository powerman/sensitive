package sensitive_test

import (
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

//nolint:paralleltest // Modifies global FormatStringFn, so can't be parallel.
func TestFormat(tt *testing.T) {
	t := check.T(tt).MustAll()

	oldFn := sensitive.FormatStringFn
	defer func() {
		sensitive.FormatStringFn = oldFn
	}()
	sensitive.FormatStringFn = func(s sensitive.String, f fmt.State, c rune) {
		sensitive.Format(f, c, string(s))
	}

	tests := []struct {
		formatting string
	}{
		{"%s"},
		{"%q"},
		{"%10s"},
		{"%.3[1]q"},
		{"%#-10v"},
	}

	for _, tc := range tests {
		t.Run(tc.formatting, func(tt *testing.T) {
			want := fmt.Sprintf(tc.formatting, "value")
			t := check.T(tt)
			result := fmt.Sprintf(tc.formatting, sensitive.String("value"))
			t.Equal(result, want)
		})
	}
}
