// Package sensitive protects secret values from accidental exposure through
// fmt, encoding/json, and similar reflection-based output, and from silent
// bugs caused by comparing secrets that hold indirections.
//
// # Choosing a type
//
// Every supported element type falls into one of two behavioral categories,
// defined by how == behaves on it:
//
//	"string" — value-comparable primitives: string, bool, int*, uint*,
//	           float32/float64, and named types over them. == compares by
//	           value. (These are exactly what Handle's Comparable accepts.)
//	"[]byte" — types whose == does NOT compare by value: []byte (compile
//	           error), decimal.Decimal (pointer-identity, silently wrong),
//	           composite structs. (These are exactly what Comparable
//	           rejects, so they cannot be a Handle element.)
//
// The choice rule is two-level:
//
//  1. "[]byte" category → [Ref].            (== does not work by value at all)
//  2. "string" category → ask whether value-== is HARMFUL:
//     harmful (password, hash — compared constant-time, never with ==) → [Ref].
//     otherwise → [Handle].
//
// So [Ref] gathers two kinds of secrets: those whose == cannot work
// ([]byte, decimals, composites), and those whose == should not be used
// (passwords, hashes). [Handle] is for value-comparable secrets where ==
// is not harmful (tokens, IDs, API keys). The two categories map exactly
// onto the Comparable constraint boundary, so the rule and the type system
// agree.
//
// Behavioral analogy: [Handle] behaves like string for == and map keys
// (value equality, valid map key); [Ref] behaves like []byte (== and map
// keys are compile errors). Use it as a fast path, then apply level 2
// (harm) for string-category secrets that must not be compared with ==.
//
// Both are structurally safe: fmt reflection cannot reach the stored value
// even through an unexported struct field. Both satisfy [Secret] via
// ExposeSecret, and both work with [reflect.DeepEqual], so tests comparing
// whole structs keep working without per-field helpers.
//
// # Comparing and indexing
//
// With [Handle], == compares by value and it is a valid map key, just like
// string. With [Ref], == is a compile-time error (as it is for []byte), so
// an accidental comparison fails loudly instead of silently returning false;
// compare values explicitly with [bytes.Equal] / [decimal.Equal] / a
// constant-time compare, or compare whole structs in tests with
// [reflect.DeepEqual]. A struct containing a Ref field is itself
// non-comparable, so == on it is also rejected — which is what you want for
// a struct holding secrets.
//
// # Why not the plain named types (String, Int, Bytes, …)
//
// The legacy [String]/[Int]/[Bytes]/… types redact only through their
// [fmt.Formatter] methods, which fmt skips the moment it descends through an
// unexported struct field — the raw value then leaks. They are kept for
// compatibility, but prefer [Ref] or [Handle] for new code: their
// protection is structural and does not depend on field visibility or on
// running a linter.
//
// # Custom named secret types
//
// For nominal type safety, wrap a box — no hand-written methods are needed,
// Format/MarshalJSON/MarshalText and ExposeSecret are promoted:
//
//	type AccessToken struct{ sensitive.Handle[string] }
//	func NewAccessToken(v string) AccessToken { return AccessToken{sensitive.Make(v)} }
//
//	type Password struct{ sensitive.Ref[string] }   // string, but == is harmful
//	func NewPassword(v string) Password { return Password{sensitive.New(v)} }
//
// For a composite secret (e.g. credentials with two sensitive fields), give
// each field its own Handle/Ref; the enclosing struct inherits
// non-comparability from any Ref field, so == on it is also a compile error.
package sensitive
