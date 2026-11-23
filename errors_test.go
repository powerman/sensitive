package sensitive_test

import (
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestErrTextSyntax(t *testing.T) {
	t.Parallel()
	tt := check.T(t)

	var r sensitive.Ref[int]
	tt.Err(r.UnmarshalText([]byte("not-an-int")), sensitive.ErrTextSyntax)
	tt.NotErr(r.UnmarshalText([]byte("not-an-int")), sensitive.ErrScanConversion)

	var h sensitive.Handle[bool]
	tt.Err(h.UnmarshalText([]byte("not-a-bool")), sensitive.ErrTextSyntax)
}

func TestErrScanConversion(t *testing.T) {
	t.Parallel()
	tt := check.T(t)

	var r sensitive.Ref[string]
	tt.Err(r.Scan(int64(1)), sensitive.ErrScanConversion)
	tt.NotErr(r.Scan(int64(1)), sensitive.ErrTextSyntax)

	var h sensitive.Handle[int64]
	tt.Err(h.Scan("not-an-int64"), sensitive.ErrScanConversion)
}
