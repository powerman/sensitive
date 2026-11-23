# Package sensitive protects secret values from accidental exposure

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/sensitive?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/sensitive/test.yml?label=test)](https://github.com/powerman/sensitive/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/sensitive/gh-badges/coverage.svg)](https://github.com/powerman/sensitive/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/powerman/sensitive?color=blue)](https://github.com/powerman/sensitive/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/sensitive.svg)](https://pkg.go.dev/github.com/powerman/sensitive)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Package `sensitive` wraps secret values — passwords, API tokens, keys —
so they cannot be leaked through `fmt`, `encoding/json`,
or any package that uses `encoding.TextMarshaler`,
and so that accidental comparisons of secrets fail loudly.

The two types to use are **`Ref[T]`** and **`Handle[T]`**.
Both keep the secret behind pointer indirections that `fmt` reflection never follows,
so the secret stays protected **regardless of how it is reached** —
even through an unexported struct field or a pointer,
where interface-based redaction silently gives up.

## Quick start

```go
type Config struct {
    Password sensitive.Ref[string] // password: comparing with == is harmful → Ref
    TenantID sensitive.Handle[int] // value-comparable, == is fine → Handle
}

func main() {
    cfg := Config{
        Password: sensitive.New("hunter2"),
        TenantID: sensitive.Make(42),
    }

    fmt.Printf("%v\n", cfg) // {REDACTED 123}

    b, _ := json.Marshal(cfg)
    fmt.Println(string(b)) // {"Password":"REDACTED","TenantID":123}

    pw := cfg.Password.ExposeSecret() // explicit opt-in to the real value
    _ = pw
}
```

## How protection works

Redaction has three independent layers.

- **Interface methods — cosmetic only.**
  `Ref`/`Handle` also implement `fmt.Formatter`, `json.Marshaler`, `encoding.TextMarshaler`,
  and `slog.LogValuer`.
  When `fmt` can reach the value on a clean path, these replace the address noise
  with a readable `REDACTED` and **preserve the redacted value's type**:
  a numeric secret stays a number, a bool stays a bool. That keeps JSON output valid
  and text-log parsers working instead of emitting a type they cannot parse.
  `slog.LogValuer` keeps this output under `slog` handlers
  which render values without the marshalers.

- **Structural protection — the real defense.**
  `Ref[T]` stores its value behind a double pointer (`**T`);
  `Handle[T]` stores it behind a single `*T` (via the runtime's `unique.Handle`).
  `fmt` reflection never dereferences these, so it can only ever print a pointer address,
  never the secret — even when the value sits behind an unexported field or a pointer,
  where the interface methods above are silently skipped.

- **In-memory encryption — last-ditch defense for string and `[]byte`.**
  `string` and `[]byte` secrets are encrypted with a random per-process AES-256 key
  before being stored in the pointer cell.
  Anyone who reaches the cell via deep reflection
  (e.g. `go-spew`, a custom serializer that follows `**T`) finds ciphertext,
  not the original value.
  This is not a memory-disclosure defense: the key lives in ordinary Go memory.
  The encryption is deterministic (equal plaintexts give equal ciphertexts),
  so a memory dump also reveals which secrets are equal and how long they are.
  It raises the bar against accidental output from tools that bypass the structural layer.

When the interface layer is bypassed, structural protection still holds:

```go
type Server struct {
    cfg Config // unexported field — fmt skips Formatter for everything beneath it
}

fmt.Printf("%+v\n", Server{cfg: cfg})
// {cfg:{Password:{_:[] pp:0x...} TenantID:{h:{value:0x...}}}}
// interface skipped, but only addresses print — the secret does not leak
```

## Choosing between Ref and Handle

The choice is driven by how `==` should behave on the secret:

- **`Ref[T]`** — when comparing the secret with `==` is wrong or harmful:
  the type's `==` does not compare by value (`[]byte`, `decimal.Decimal`, composite structs),
  or the secret is a password or a hash, which must be compared constant-time.
  `Ref` makes `==` a **compile-time error**,
  so an accidental comparison fails loudly instead of silently returning `false`.

- **`Handle[T]`** — for value-comparable primitive secrets where `==` is fine:
  bearer tokens, session IDs, API keys.
  `==` compares by value and a `Handle` is a valid map key.

Both are structurally protected, both work with `reflect.DeepEqual`,
and both satisfy the `Secret[T]` interface via `ExposeSecret`.
Wrap either one for a nominal type:

```go
type Password struct{ sensitive.Ref[string] }       // == is harmful   → Ref
type AccessToken struct{ sensitive.Handle[string] } // safe to compare → Handle
```

## Ingesting and persisting secrets

`*Ref[T]` and `*Handle[T]` implement `json.Unmarshaler`,
`encoding.TextUnmarshaler`, and `database/sql.Scanner`,
so a secret from a config or a database row lands **directly** in a protected field
and is never materialized as a plain `string`/`[]byte` which could be logged by accident:

```go
var pw sensitive.Ref[string]
err := db.QueryRow(`SELECT password FROM users WHERE id = ?`, id).Scan(&pw)
```

`Ref`/`Handle` do **not** implement `driver.Valuer`,
so the secret cannot reach the driver without a visible `ExposeSecret*` at the call site:

```go
_, err := db.Exec(`UPDATE users SET password = ? WHERE id = ?`,
    cfg.Password.ExposeSecretValuer(), id)
```

`ExposeSecretValuer` returns a `SecretValuer[T]`,
which exposes the secret only to `driver.Valuer`, `json.Marshaler` and `encoding.TextMarshaler`,
while `fmt` and `slog` output stays redacted.
It also implements the same ingest interfaces,
so it works as a round-trip DTO for the database or the wire.

> **Keep `SecretValuer` confined to the DTO.**
> Unlike `driver.Valuer`, `MarshalJSON`/`MarshalText` have an open consumer set
> (HTTP body, cache).
> Do not `json.Marshal` a struct that holds a live `SecretValuer` into a log or error message.

## When interface-only redaction breaks

Types that protect a secret **only** through interfaces
(`go-playground/sensitive`, `negrel/secrecy`, `angusgmorrison/logfusc`)
redact only while `fmt` reaches the value on a clean path.
Redaction silently disappears when the secret is reached through an unexported struct field,
a pointer on the path, or the builtin `print`/`println` — among other subtle cases.
For the full list of failure modes and examples, see the
[lint-sensitive README](https://github.com/powerman/lint-sensitive#how-protection-silently-breaks).

`Ref` and `Handle` are immune to all of these because their protection is structural,
not interface-based.

## Comparison with other libraries

| Feature                                                 | `sensitive` `Ref`/`Handle` | `rsjethani/secret` | `andrewbenton/go-secrets` | `go-playground/sensitive` | `negrel/secrecy` | `angusgmorrison/logfusc` |
| ------------------------------------------------------- | -------------------------- | ------------------ | ------------------------- | ------------------------- | ---------------- | ------------------------ |
| Structural protection (survives unexported / pointer)   | ✓                          | ✓                  | ✓                         | ✗                         | ✗                | ✗                        |
| Redacts under **all** `fmt` verbs (`fmt.Formatter`)     | ✓                          | ✗⁵                 | ✗⁵                        | ✓                         | ✗                | ✗                        |
| Redacts under `%v`/`%s`/`%#v` (`Stringer`/`GoStringer`) | ✓                          | ~⁵                 | ~⁵                        | ✓                         | ✓                | ✓                        |
| JSON redaction                                          | ✓                          | ✓                  | ✓¹                        | ✓                         | ✓                | ✓                        |
| `encoding.TextMarshaler` redaction                      | ✓                          | ✓                  | ✗                         | ✓                         | ✓                | ✗                        |
| Type-preserving redaction (number stays a number)       | ✓                          | —                  | ~¹                        | ✗                         | ✗                | ✗                        |
| Customizable redaction output                           | ✓                          | ✓                  | ✗                         | ✓                         | ✓                | ✗                        |
| Ingest via `json.Unmarshaler`                           | ✓                          | ~²                 | ✓                         | ✗                         | ✓                | ✓                        |
| Ingest via `encoding.TextUnmarshaler`                   | ✓                          | ✓                  | ✗                         | ✗                         | ✗                | ✗                        |
| DB read via `database/sql.Scanner`                      | ✓                          | ✗                  | ✗                         | ✗                         | ✗                | ✗                        |
| DB write via `driver.Valuer`                            | ✓                          | ✗                  | ✗                         | ✗                         | ✗                | ✗                        |
| Value `==` equality                                     | `Handle` ✓ / `Ref` ✗       | ✗³                 | ✗                         | ✓                         | ✗                | ✗                        |
| Valid map key                                           | `Handle` ✓ / `Ref` ✗       | ✗³                 | ✗                         | ✓                         | ✗                | ✗                        |
| Works with `reflect.DeepEqual`                          | ✓                          | ✓                  | ✗                         | ✓                         | ✓                | ✓                        |
| Any element type (generic)                              | ✓                          | ✗                  | ✓                         | ✗                         | ✓                | ✓                        |
| Memory zeroization                                      | ✗⁴                         | ✗                  | ✗                         | ✗                         | ✓                | ✗                        |

¹ — `go-secrets` marshals the zero value of `T`: redaction exists but is not configurable
and is only meaningful for JSON.<br/>
² — `encoding/json` picks up its `TextUnmarshaler` for string fields,
so JSON ingest works for strings only.<br/>
³ — `==` compiles but compares the internal `*string` by identity (silently wrong);
its `Equal` helper must be used instead.<br/>
⁴ — deferred by design, see [Memory zeroization](#memory-zeroization).<br/>
⁵ — implements `Stringer` but neither `Formatter` nor `GoStringer`:
`%#v` and other verbs print internal pointers or closures instead of a redacted value.
This is structurally safe (the secret does not leak), but it is not redaction.

## Redaction output

`Redact()` is the default policy, so no setup is needed.
Change the policy at startup if you need a different one:

- `sensitive.Redact()` — replace each secret with a visible, type-preserving
  sentinel: `"REDACTED"` for strings, `0xDEFACE` for bytes
  (`DEFACE` as text, base64 `3vrO` in JSON), `false` for bool,
  and the same number `123` for every int, uint, float and decimal.
  Call it to restore the default policy after a change.
- `sensitive.Disable()` — print the real value, for tests only.
  It is a no-op unless the binary name ends in `.test`
  and `GO_TEST_DISABLE_SENSITIVE` is not empty,
  minimizing the chance of disabling protection in production.
- Override an individual `Format<Type>Fn` for custom output (e.g. show the first few characters):

  ```go
  sensitive.FormatStringFn = func(s string, f fmt.State, c rune) {
      sensitive.Format(f, c, s[:min(4, len(s))]+"…")
  }
  ```

## Memory zeroization

Unlike `negrel/secrecy`, `Ref` and `Handle` do not wipe the secret from memory
via `runtime.SetFinalizer`: finalizers are unreliable here
(strings are immutable, Go moves values in memory, the GC copies).
The right vehicle is the experimental `runtime/secret` package,
and support is deferred until it stabilizes.

## Examples

Runnable programs live in [`_examples/`](_examples/):

- [`basic`](_examples/basic/main.go) — `Ref` with the default redaction.
- [`custom`](_examples/custom/main.go) — custom redaction via `FormatStringFn`.
- [`handle`](_examples/handle/main.go) — `Handle` value equality and map keys.
