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
// Comparing such structs with go-cmp requires an option, see [CmpExporter].
//
// # How protection works
//
// Protection has several independent layers, but only one carries the guarantee.
//
// The [fmt.Formatter], [json.Marshaler], [encoding.TextMarshaler] and [slog.LogValuer] methods
// are only cosmetic, adding readable REDACTED output on the clean paths where they are reached.
// [slog.LogValuer] keeps this output under slog handlers
// which render values without the marshalers.
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
// so a memory dump also reveals which secrets are equal and how long they are.
//
// # Redaction output
//
// By default each secret is replaced with a visible value of the original type, see [Redact].
// Replace any Format<Type>Fn variable to customize the output,
// or call [Disable] in tests to output the real values.
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
// A Ref of the whole struct protects it too,
// but it is printed and marshaled as nil, see [Ref].
package sensitive
