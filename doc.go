// Package sensitive protects secret values from accidental exposure through
// fmt, encoding/json, other packages that use [encoding.TextMarshaler],
// and from silent bugs caused by comparing secrets that hold indirections.
//
// # Choosing a type
//
// The choice is driven by how == should behave on the secret:
//
//  1. == does NOT compare by value
//     → [Ref]: []byte (compile error),
//     decimal.Decimal (pointer identity, silently wrong), composite structs.
//     These are exactly what [Comparable] rejects, so they cannot be a [Handle].
//
//  2. == compares by value
//     (string, bool, int*, uint*, float*, and named types over them —
//     exactly what [Comparable] accepts)
//     → ask whether using == is HARMFUL:
//
//     - harmful (passwords, hashes — compared constant-time,
//     never with ==) → [Ref].
//
//     - otherwise (tokens, IDs, API keys) → [Handle].
//
//  3. For ingress/egress DTO — the secret crosses a system boundary:
//     database, JSON/text serialization.
//     → [SecretValuer], a combined egress+ingress type
//     that exposes the secret to trusted sinks
//     while staying redaction-safe under [fmt] and [slog].
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
//
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
// The [fmt.Formatter] method, by contrast, is only cosmetic,
// adding readable REDACTED output on the clean paths where fmt can reach the value.
//
// The [slog.LogValuer] method redacts in [slog.Value.Resolve],
// before a handler chooses how to render the value,
// while the marshalers help only if the handler happens to choose them.
// It adds no protection, only readable output:
// a handler which calls Resolve but renders values without the marshalers (e.g. by reflection)
// would otherwise print internals of the value instead of the redacted one.
// A handler which never calls Resolve violates the [slog.Handler] contract and does not benefit.
//
// Structural protection is the real defense against fmt:
// both [Ref] and [Handle] keep the value behind a pointer that fmt reflection never follows,
// so it can only ever reach a pointer address, never the secret.
//
// In-memory encryption is an add-on for string and []byte only:
// those are stored as ciphertext under a random per-process AES-256 key,
// raising the bar against deep-reflection tools (go-spew, custom **T serializers)
// that bypass the structural protection against fmt.
// It is not a memory-disclosure defense — the key lives in ordinary Go memory,
// unlike a mlock/guarded-page approach such as memguard.
// The encryption is deterministic (equal plaintexts give equal ciphertexts),
// because [Handle] interns its values and [reflect.DeepEqual] must keep working on both types.
// So a memory dump also reveals which secrets are equal and how long they are.
//
// # Why typed redacted values
//
// By default (as if [Redact] was called), each sensitive type is replaced with a visible but
// safe value that preserves the original's type:
//
//	Bool    → false               (still a bool in JSON)
//	Float*  → 123                 (still a number in JSON)
//	Int*    → 123                 (still a number in JSON)
//	Uint*   → 123                 (still a number in JSON)
//	String  → "REDACTED"          (still a string in JSON)
//	Bytes   → 0xDEFACE            (base64 string "3vrO" in JSON, DEFACE in text)
//	Decimal → 123                 (decimal's own JSON form: "123" or 123,
//	                               see decimal.MarshalJSONWithoutQuotes)
//
// Keeping the original's type means that if a secret accidentally ends up in JSON output,
// the JSON structure stays valid and parseable — a numeric field remains a number,
// a boolean field remains a boolean. Text log parsers that expect specific field types
// (such as structured loggers emitting typed values)
// likewise keep working instead of failing on a type mismatch.
//
// All numbers share one short sentinel, 123:
// it is easy to spot and to assert in tests,
// unlike 0 it does not claim a false fact (balance=0),
// and it is exactly representable in any numeric type (int8, float32, decimal).
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
