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
// The choice is driven by how == should behave on the secret:
//
//  1. == does NOT compare by value → [Ref]: []byte (compile error),
//     decimal.Decimal (pointer identity, silently wrong), composite structs.
//     (These are exactly what [Comparable] rejects, so they cannot be a Handle.)
//  2. == compares by value (string, bool, int*, uint*, float*, and named types
//     over them — exactly what [Comparable] accepts) → ask whether using == is HARMFUL:
//     harmful (passwords, hashes — compared constant-time, never with ==) → [Ref].
//     otherwise (tokens, IDs, API keys) → [Handle].
//
// Behavioral analogy: [Handle] behaves like string (value ==, valid map key);
// [Ref] behaves like []byte (== and map keys are compile errors).
//
// Both are structurally-protected: fmt reflection cannot reach the stored value
// even through an unexported struct field.
// Both satisfy [Secret] via ExposeSecret, and both work with [reflect.DeepEqual],
// so tests comparing whole structs keep working without per-field helpers.
//
// # Comparing and indexing
//
// With [Handle], == and map keys work by value, just like string.
// With [Ref], == is a compile-time error (as it is for []byte),
// so an accidental comparison fails loudly instead of silently returning false;
// compare values explicitly with [bytes.Equal] / [decimal.Equal] / a constant-time compare,
// or compare whole structs in tests with [reflect.DeepEqual].
// A struct containing a Ref field is itself non-comparable —
// which is what you want for a struct holding secrets.
//
// # How protection works
//
// Protection has several independent layers, but only one carries the guarantee.
//
// The [json.Marshaler] and [encoding.TextMarshaler] methods
// are the sole defense against serialization: encoders walk only exported fields,
// so structural protection never engages, but these methods always run.
//
// Structural protection is the real defense against fmt:
// both [Ref] and [Handle] keep the value behind a pointer that fmt reflection never follows,
// so it can only ever reach a pointer address, never the secret.
//
// The [fmt.Formatter] method, by contrast, is only cosmetic,
// adding readable REDACTED output on the clean paths where fmt can reach the value.
//
// In-memory encryption is an add-on for string and []byte only:
// those are stored as ciphertext under a random per-process AES-256 key,
// raising the bar against deep-reflection tools (go-spew, custom **T serializers)
// that bypass the structural protection against fmt.
// It is not a memory-disclosure defense — the key lives in ordinary Go memory,
// unlike a mlock/guarded-page approach such as memguard.
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
