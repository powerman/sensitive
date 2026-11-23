package sensitive_test

import (
	"reflect"
	"testing"
	"unique"

	"github.com/google/go-cmp/cmp"
	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

type cmpPassword struct{ sensitive.Ref[string] }

type cmpConfig struct {
	Name     string
	Password sensitive.Ref[string]
	Token    sensitive.Handle[string]
	Port     sensitive.Handle[int]
	Creds    sensitive.Ref[testStruct]
	Valuer   sensitive.SecretValuer[string]
	Named    cmpPassword
	Ptr      *sensitive.Ref[int]
	List     []sensitive.Ref[[]byte]
	Map      map[string]sensitive.Handle[int]
	Any      any
}

func newCmpConfig(secret string) cmpConfig {
	n := len(secret)
	ptr := sensitive.New(n)
	return cmpConfig{
		Name:     "cfg",
		Password: sensitive.New(secret),
		Token:    sensitive.Make(secret),
		Port:     sensitive.Make(n),
		Creds:    sensitive.New(testStruct{A: secret, B: n}),
		Valuer:   sensitive.New(secret).ExposeSecretValuer(),
		Named:    cmpPassword{sensitive.New(secret)},
		Ptr:      &ptr,
		List:     []sensitive.Ref[[]byte]{sensitive.New([]byte(secret))},
		Map:      map[string]sensitive.Handle[int]{"k": sensitive.Make(n)},
		Any:      sensitive.New(secret),
	}
}

func TestCmpExporter(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt)

	t.True(sensitive.CmpExporter(reflect.TypeFor[sensitive.Ref[string]]()))
	t.True(sensitive.CmpExporter(reflect.TypeFor[sensitive.Ref[testStruct]]()))
	t.True(sensitive.CmpExporter(reflect.TypeFor[sensitive.Handle[int]]()))
	t.True(sensitive.CmpExporter(reflect.TypeFor[sensitive.SecretValuer[string]]()))
	t.True(sensitive.CmpExporter(reflect.TypeFor[unique.Handle[string]]()))

	t.False(sensitive.CmpExporter(reflect.TypeFor[int]()))
	t.False(sensitive.CmpExporter(reflect.TypeFor[testStruct]()))
	t.False(sensitive.CmpExporter(reflect.TypeFor[cmpPassword]()))
	t.False(sensitive.CmpExporter(reflect.TypeFor[*sensitive.Ref[string]]()))
	t.False(sensitive.CmpExporter(reflect.TypeFor[[]sensitive.Ref[string]]()))
	t.False(sensitive.CmpExporter(reflect.TypeFor[reflect.Type]()))
}

func TestCmpExporter_cmp(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt)

	opt := cmp.Exporter(sensitive.CmpExporter)

	t.True(cmp.Equal(newCmpConfig("secret"), newCmpConfig("secret"), opt))
	t.False(cmp.Equal(newCmpConfig("secret"), newCmpConfig("other"), opt))

	// Each secret is compared, not ignored.
	for _, mutate := range []func(*cmpConfig){
		func(c *cmpConfig) { c.Password = sensitive.New("other") },
		func(c *cmpConfig) { c.Token = sensitive.Make("other") },
		func(c *cmpConfig) { c.Port = sensitive.Make(42) },
		func(c *cmpConfig) { c.Creds = sensitive.New(testStruct{A: "other"}) },
		func(c *cmpConfig) { c.Valuer = sensitive.New("other").ExposeSecretValuer() },
		func(c *cmpConfig) { c.Named = cmpPassword{sensitive.New("other")} },
		func(c *cmpConfig) { p := sensitive.New(42); c.Ptr = &p },
		func(c *cmpConfig) { c.List = []sensitive.Ref[[]byte]{sensitive.New([]byte("other"))} },
		func(c *cmpConfig) { c.Map = map[string]sensitive.Handle[int]{"k": sensitive.Make(42)} },
		func(c *cmpConfig) { c.Any = sensitive.New("other") },
	} {
		other := newCmpConfig("secret")
		mutate(&other)
		t.False(cmp.Equal(newCmpConfig("secret"), other, opt))
	}

	// Zero values are equal to secrets created from the zero value.
	t.True(cmp.Equal(sensitive.Ref[string]{}, sensitive.New(""), opt))
	t.True(cmp.Equal(sensitive.Handle[int]{}, sensitive.Make(0), opt))
	t.False(cmp.Equal(sensitive.Ref[string]{}, sensitive.New("x"), opt))
}

func TestCmpExporter_combined(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt)

	type mine struct{ v int }
	type holder struct {
		M mine
		S sensitive.Handle[string]
	}
	isMine := func(t reflect.Type) bool { return t == reflect.TypeFor[mine]() }

	a := holder{mine{1}, sensitive.Make("x")}
	b := holder{mine{2}, sensitive.Make("x")}
	combined := cmp.Exporter(func(t reflect.Type) bool { return sensitive.CmpExporter(t) || isMine(t) })
	t.True(cmp.Equal(a, a, combined))
	t.False(cmp.Equal(a, b, combined))
	several := []cmp.Option{cmp.Exporter(sensitive.CmpExporter), cmp.Exporter(isMine)}
	t.True(cmp.Equal(a, a, several...))
	t.False(cmp.Equal(a, b, several...))
}
