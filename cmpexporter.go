package sensitive

import (
	"reflect"
	"strings"
	"unique"
)

// CmpExporter reports whether t is a [Ref], [Handle] or [SecretValuer],
// or the internal type which [Handle] is built on.
//
// The go-cmp module (and gotest.tools and quicktest, which use it) panics on unexported fields,
// and all fields of these types are unexported.
// To compare structs containing them, pass CmpExporter to cmp.Exporter:
//
//	cmp.Equal(want, got, cmp.Exporter(sensitive.CmpExporter))
//
// To also export your own types, combine the predicates
// (or pass several cmp.Exporter options, any of them may match):
//
//	cmp.Exporter(func(t reflect.Type) bool { return sensitive.CmpExporter(t) || isMine(t) })
//
// Do not use cmpopts.IgnoreUnexported instead: it makes any two secrets compare as equal.
// When a comparison fails, go-cmp (like any other reflection-based tool)
// prints the internals of the secrets, see the package documentation.
func CmpExporter(t reflect.Type) bool {
	name, _, generic := strings.Cut(t.Name(), "[")
	if !generic {
		return false
	}
	switch t.PkgPath() {
	case reflect.TypeFor[Ref[any]]().PkgPath():
		return name == "Ref" || name == "Handle" || name == "SecretValuer"
	case reflect.TypeFor[unique.Handle[int]]().PkgPath():
		return name == "Handle"
	default:
		return false
	}
}
