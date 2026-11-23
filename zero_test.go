package sensitive_test

import (
	"reflect"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

func TestZeroNormalization(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt)

	t.True(sensitive.Make("") == sensitive.Handle[string]{})
	t.True(sensitive.Make(0) == sensitive.Handle[int]{})
	t.True(sensitive.Make(namedString("")) == sensitive.Handle[namedString]{})
	t.True(sensitive.Make("x") != sensitive.Handle[string]{})

	t.DeepEqual(sensitive.New(""), sensitive.Ref[string]{})
	t.DeepEqual(sensitive.New(0), sensitive.Ref[int]{})
	t.DeepEqual(sensitive.New([]byte(nil)), sensitive.Ref[[]byte]{})
	t.DeepEqual(sensitive.New(testStruct{}), sensitive.Ref[testStruct]{})
	t.DeepEqual(sensitive.New[any](nil), sensitive.Ref[any]{})
	t.True(reflect.DeepEqual(sensitive.New("x"), sensitive.New("x")))
	t.False(reflect.DeepEqual(sensitive.New("x"), sensitive.Ref[string]{}))

	t.True(sensitive.New("").IsZero())
	t.Equal(sensitive.New("").ExposeSecret(), "")
	t.Equal(sensitive.Make("").ExposeSecret(), "")

	// A non-nil empty []byte is not a zero value and keeps its identity.
	t.NotNil(sensitive.New([]byte{}).ExposeSecret())
}
