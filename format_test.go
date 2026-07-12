package sensitive_test

import (
	"fmt"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

//nolint:paralleltest // Modifies global FormatStringFn, so can't be parallel.
func TestFormat(t *testing.T) {
	oldFn := sensitive.FormatStringFn
	defer func() {
		sensitive.FormatStringFn = oldFn
	}()
	sensitive.FormatStringFn = func(s string, f fmt.State, c rune) {
		sensitive.Format(f, c, s)
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
			t := check.Must(tt)
			result := fmt.Sprintf(tc.formatting, "value")
			t.Equal(result, want)
		})
	}
}
