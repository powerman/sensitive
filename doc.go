// Package sensitive protects secret values from accidental exposure through
// fmt, encoding/json, and similar reflection-based output, and from silent
// bugs caused by comparing secrets that hold indirections.
//
// Use only [Handle], [Ref], and the [Secret] interface for new code.
// All other types in this package are deprecated legacy types kept for
// compatibility — see the "Why not the plain named types" section.
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
// # Why these storage shapes
//
// Both boxes protect a secret by storing it behind a shape that fmt
// reflection can only print as an address, never as the value.
// The shapes are chosen so each box also gives the right == behavior:
//
//   - [Ref] stores T behind **T. A single *T would still allow ==
//     (pointer identity, silently wrong for a value); **T makes == a
//     compile-time error, while [reflect.DeepEqual] still reads through
//     both levels and compares by value — so tests comparing whole
//     structs keep working. This is the right shape for secrets whose
//     direct == is unsafe (passwords, hashes are compared constant-time,
//     never with ==) and for types whose == does not compare by value at
//     all ([]byte, decimals, composites).
//
//   - [Handle] stores T behind [unique.Handle], which canonicalizes equal
//     values to one pointer, giving value == and a valid map key. That is
//     the only safe way to give a secret a value ==:
//     a bare *any is no better than **T (still pointer identity, no
//     canonicalization); chan/func fields would break [reflect.DeepEqual]
//     too; [unsafe.Pointer] is too costly and unsafe to rely on; no other
//     safe variant exists. For the non-compound types [Comparable] admits
//     today (primitives and named types over them) a single
//     [unique.Handle][T] is enough — fmt prints its *T as an address. A
//     compound T (e.g. a struct-based type like decimal.Decimal but WITHOUT
//     an internal pointer, with honest value ==) would need one extra
//     indirection (nesting [unique.Handle] one level deeper) — see the
//     Comparable invariant in handle.go. That nesting is deferred: it is
//     overkill today, and there is a high probability no compound type is
//     ever added to Comparable.
//
// "Compound types we might add to Comparable" never means slice/map
// types. They cannot be a [unique.Handle][T] element ([unique.Handle]
// requires Go's standard comparable constraint, which excludes slices
// and maps), and [Handle] differs from [Ref] only by supporting == —
// which slices and maps never had in Go, and which this package does not
// set out to add.
//
// # Why not the plain named types (String, Int, Bytes, …)
//
// The [String]/[Int]/[Bytes]/… types are deprecated legacy types kept only for
// compatibility. They redact through their [fmt.Formatter] methods, which fmt
// skips the moment it descends through an unexported struct field — the raw
// value then leaks through JSON/text encoding. Do not use them in new code.
// Use [Handle] or [Ref] instead (plus the [Secret] interface where needed):
// their protection is structural and does not depend on field visibility or on
// running a linter.
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
// Using type-specific sentinels means that if a secret accidentally ends up in
// JSON output, the JSON structure stays valid and parseable — a numeric field
// remains a number, a boolean field remains a boolean. Text log parsers that
// expect specific field types (such as structured loggers emitting typed
// values) likewise keep working instead of failing on a type mismatch.
// This is especially important in pre-production or debugging configurations
// where [Redact] is used: the shape of the data must be preserved even though
// the actual secret value is hidden.
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
