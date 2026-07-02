// Package sensitive protects secret values from accidental exposure through
// fmt, encoding/json, other packages that use [encoding.TextMarshaler],
// and from silent bugs caused by comparing secrets that hold indirections.
//
// Use only [Handle], [Ref], and the [Secret] interface for new code.
// All other types in this package are deprecated legacy types
// kept for compatibility — see the "Why not the plain named types" section.
//
// # Choosing a type
//
// Every secret kind falls into one of two behavioral categories,
// defined by how == behaves on it:
//
//	"string" — value-comparable primitives: string, bool, int*, uint*, float*,
//	           and named types over them. == compares by value.
//	           (These are exactly what Handle's [Comparable] accepts.)
//	"[]byte" — types whose == does NOT compare by value: []byte (compile error),
//	           decimal.Decimal (pointer-identity, silently wrong), composite structs.
//	           (These are exactly what [Comparable] rejects,
//	           so they cannot be a Handle element.)
//
// The choice rule is two-level:
//
//  1. "[]byte" category → [Ref].            (== does not work by value at all)
//  2. "string" category → ask whether value-== is HARMFUL:
//     harmful (password, hash — compared constant-time, never with ==) → [Ref].
//     otherwise → [Handle].
//
// [Ref] gathers two kinds of secrets: those whose == cannot work ([]byte, decimals, composites),
// and those whose == should not be used (passwords, hashes).
// [Handle] is for value-comparable secrets where == is not harmful (tokens, IDs, API keys).
//
// Behavioral analogy: [Handle] behaves like string for == and map keys
// (value equality, valid map key);
// [Ref] behaves like []byte (== and map keys are compile errors).
// Use it as a fast path, then apply level 2 (harm) for string-category secrets
// that must not be compared with ==.
//
// Both are structurally-protected: fmt reflection cannot reach the stored value
// even through an unexported struct field.
// Both satisfy [Secret] via ExposeSecret, and both work with [reflect.DeepEqual],
// so tests comparing whole structs keep working without per-field helpers.
//
// # Comparing and indexing
//
// With [Handle], == compares by value and it is a valid map key, just like string.
// With [Ref], == is a compile-time error (as it is for []byte),
// so an accidental comparison fails loudly instead of silently returning false;
// compare values explicitly with [bytes.Equal] / [decimal.Equal] / a constant-time compare,
// or compare whole structs in tests with [reflect.DeepEqual].
// A struct containing a Ref field is itself non-comparable,
// so == on it is also rejected — which is what you want for a struct holding secrets.
//
// # Why not the plain named types (String, Int, Bytes, …)
//
// The [String]/[Int]/[Bytes]/… types are deprecated legacy types kept only for compatibility.
// They redact through their [fmt.Formatter] methods,
// which fmt skips the moment it descends through an unexported struct field or a pointer —
// the raw value then leaks.
// If you have to use them, then use https://github.com/powerman/lint-sensitive/
// to detect accidental exposure through fmt.
//
// # Why typed redacted values
//
// When you call [Redact], each sensitive type is replaced with a visible but
// safe value that preserves the original's type:
//
//	Bool    → FALSE               (still a bool in JSON)
//	Float*  → NaN                 (still a number in JSON)
//	Int*    → math.MinInt*        (still a number in JSON)
//	Uint*   → math.MaxUint*       (still a number in JSON)
//	String  → "REDACTED"          (still a string in JSON)
//	Bytes   → 0xDEFACE            (still a byte slice)
//	Decimal → NaN                 (still a number in JSON)
//
// Using type-specific sentinels means that if a secret accidentally ends up in JSON output,
// the JSON structure stays valid and parseable — a numeric field remains a number,
// a boolean field remains a boolean. Text log parsers that expect specific field types
// (such as structured loggers emitting typed values)
// likewise keep working instead of failing on a type mismatch.
//
// # Custom named secret types
//
// For nominal type safety, just wrap a box:
//
//	type AccessToken struct{ sensitive.Handle[string] }
//	func NewAccessToken(v string) AccessToken { return AccessToken{sensitive.Make(v)} }
//
//	type Password struct{ sensitive.Ref[string] }   // string, but == is harmful
//	func NewPassword(v string) Password { return Password{sensitive.New(v)} }
//
// For a composite secret (e.g. credentials with two sensitive fields),
// give each field its own Handle/Ref.
package sensitive
