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

> The legacy named types (`String`, `Int`, `Bytes`, …) are **deprecated** and
> kept only for compatibility. They rely on interfaces alone and can leak — see
> [Deprecated legacy types](#deprecated-legacy-types).

## Quick start

```go
type Config struct {
    Password sensitive.Ref[string] // password: comparing with == is harmful → Ref
    TenantID sensitive.Handle[int] // value-comparable, == is fine → Handle
}

func main() {
    sensitive.Redact() // enable REDACTED-style output; call once at startup

    cfg := Config{
        Password: sensitive.New("hunter2"),
        TenantID: sensitive.Make(42),
    }

    fmt.Printf("%v\n", cfg) // {REDACTED -2147483648}

    b, _ := json.Marshal(cfg)
    fmt.Println(string(b)) // {"Password":"REDACTED","TenantID":-2147483648}

    pw := cfg.Password.ExposeSecret() // explicit opt-in to the real value
    _ = pw
}
```

## How protection works

Redaction has two independent layers, and only one of them is a real defense.

- **Structural protection — the real defense.**
  `Ref[T]` stores its value behind a double pointer (`**T`);
  `Handle[T]` stores it behind a single `*T` (via the runtime's `unique.Handle`).
  `fmt` reflection never dereferences these, so it can only ever print a pointer address,
  never the secret — even when the value sits behind an unexported field or a pointer,
  where the interface methods below are silently skipped.

- **Interface methods — cosmetic only.**
  `Ref`/`Handle` also implement `fmt.Formatter`, `json.Marshaler`, and `encoding.TextMarshaler`.
  When `fmt` can reach the value on a clean path, these replace the address noise
  with a readable `REDACTED` and, crucially, **preserve the redacted value's type**:
  a numeric secret stays a number, a bool stays a bool. That keeps JSON output valid
  and text-log parsers working instead of emitting a type they cannot parse.

The point: the pretty `REDACTED` output is a nicety; the guarantee that the raw
secret never reaches your logs comes from the structural layer alone.
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
  - the type's `==` does not compare by value: `[]byte` (compile error),
    `decimal.Decimal` (pointer identity, silently wrong), composite structs; or
  - `==` works but must not be used: passwords and hashes are compared constant-time,
    never with `==`.

  `Ref` makes `==` a **compile-time error**,
  so an accidental comparison fails loudly instead of silently returning `false`.
  It is non-comparable and not a valid map key; compare values explicitly
  (`bytes.Equal`, `decimal.Decimal.Equal`, a constant-time compare)
  or whole structs in tests with `reflect.DeepEqual`.

- **`Handle[T]`** — for value-comparable primitive secrets where `==` is fine:
  bearer tokens, session IDs, API keys.
  `==` compares by value and a `Handle` is a valid map key.
  `T` is restricted to primitive comparable types
  (string, bool, integers, floats, and named types over them).

Both are structurally protected, both work with `reflect.DeepEqual`,
and both satisfy the `Secret[T]` interface via `ExposeSecret`.
Wrap either one for a nominal type:

```go
type Password struct{ sensitive.Ref[string] }       // == is harmful   → Ref
type AccessToken struct{ sensitive.Handle[string] } // safe to compare → Handle
```

## Ingesting and persisting secrets

A secret often arrives from JSON/YAML config or a database row
and later has to be written back to a database.
`Ref` and `Handle` implement the interfaces that let the secret land
**directly** in the protected field and leave it through the driver
**explicitly** — never materialized as a plain `string`/`[]byte`
in application code, where it could be logged by accident.

### Ingest: unmarshal and scan into a Ref/Handle

`*Ref[T]` and `*Handle[T]` implement `json.Unmarshaler`,
`encoding.TextUnmarshaler`, and `database/sql.Scanner`,
so external data can be deserialized straight into a protected field:

```go
type Config struct {
    Password sensitive.Ref[string]
    TenantID sensitive.Handle[int]
}

var cfg Config
_ = json.Unmarshal(configBytes, &cfg) // lands in Ref/Handle, never a plain string
```

Reading a secret column from the database works the same way:

```go
var pw sensitive.Ref[string]
err := db.QueryRow(`SELECT password FROM users WHERE id = ?`, id).Scan(&pw)
```

Prefer this over scanning into a plain `string` and then calling `sensitive.New`:
the intermediate plain value has no structural protection and can be logged
by any `fmt.Printf` added to that code path later.

### Persist: write to the database with ExposeSecretValuer

`Ref`/`Handle` do **not** implement `driver.Valuer` directly —
that would let the secret flow to the driver through an implicit interface
call with no visible `ExposeSecret*` at the call site.
Instead, call `ExposeSecretValuer()` to get a `SecretValuer[T]`
that implements `driver.Valuer` while staying redaction-safe everywhere else:

```go
_, err := db.Exec(`UPDATE users SET password = ? WHERE id = ?`,
    cfg.Password.ExposeSecretValuer(), id)
```

`SecretValuer` is structurally protected and redacts under `fmt`/`json`,
so even if the wrapper is logged by accident the secret does not leak —
the plaintext reaches only the database driver.

## When interface-only redaction breaks

Types that protect a secret **only** through interfaces (the deprecated named
types here, `go-playground/sensitive`, `negrel/secrecy`, `angusgmorrison/logfusc`)
redact only while `fmt` reaches the value on a clean path.
Redaction silently disappears when the secret is reached through an unexported struct field,
a pointer on the path, or the builtin `print`/`println` — among other subtle cases.
For the full list of failure modes and examples, see the
[lint-sensitive README](https://github.com/powerman/lint-sensitive#how-protection-silently-breaks).

`Ref` and `Handle` are immune to all of these because their protection is structural,
not interface-based. If you must keep the deprecated named types,
run [lint-sensitive](https://github.com/powerman/lint-sensitive) in CI
to catch the leaks statically.

## Comparison with other libraries

| Feature                                               | `sensitive` `Ref`/`Handle` | `rsjethani/secret` | `andrewbenton/go-secrets` | `sensitive` `String`… (legacy) | `go-playground/sensitive` | `negrel/secrecy` | `angusgmorrison/logfusc` |
| ----------------------------------------------------- | -------------------------- | ------------------ | ------------------------- | ------------------------------ | ------------------------- | ---------------- | ------------------------ |
| Structural protection (survives unexported / pointer) | ✓                          | ✓⁷                 | ✓⁸                        | ✗                              | ✗                         | ✗                | ✗                        |
| Redacts under **all** `fmt` verbs (`fmt.Formatter`)   | ✓                          | ✓⁷                 | ✓⁸                        | ✓                              | ✓                         | ✗¹               | ✗¹                       |
| JSON redaction                                        | ✓                          | ✓                  | ✓⁹                        | ✓                              | ✓                         | ✓                | ✓                        |
| `encoding.TextMarshaler` redaction                    | ✓                          | ✓                  | ✗                         | ✓                              | ✓                         | ✓                | ✗                        |
| Type-preserving redaction (number stays a number)     | ✓                          | —¹⁰                | ~⁹                        | ✓                              | ✗                         | ✗                | ✗                        |
| Customizable redaction output                         | ✓                          | ✓                  | ✗                         | ✓                              | ✓                         | ~²               | ✗                        |
| Ingest via `json.Unmarshaler`/`TextUnmarshaler`       | ✓                          | ~¹³                | ~¹⁴                       | ✗                              | ✗                         | ~¹⁴              | ~¹⁴                      |
| DB read via `database/sql.Scanner`                    | ✓                          | ✗                  | ✗                         | ✗                              | ✗                         | ✗                | ✗                        |
| DB write via `driver.Valuer`                          | ✓¹⁵                        | ✗                  | ✗                         | ✗                              | ✗                         | ✗                | ✗                        |
| Value `==` equality                                   | `Handle` ✓ / `Ref` ✗³      | ✗¹¹                | ✗                         | ✓⁶                             | ✓                         | ✗                | ✗                        |
| Valid map key                                         | `Handle` ✓ / `Ref` ✗       | ✗¹¹                | ✗                         | ✓⁶                             | ✓                         | ✗                | ✗                        |
| Works with `reflect.DeepEqual`                        | ✓                          | ✓                  | ✗¹²                       | ✓                              | ✓                         | ✓                | ✓                        |
| Any element type (generic)                            | ✓                          | ✗¹⁰                | ✓                         | ✗⁴                             | ✗⁴                        | ✓                | ✓                        |
| Memory zeroization                                    | ✗⁵                         | ✗                  | ✗                         | ✗                              | ✗                         | ✓                | ✗                        |

¹ — only `fmt.Stringer`/`GoStringer`, so `%v`/`%s`/`%#v` redact but verbs they do not cover
can still print the raw value.<br/>
² — a single global marker string, not per-type or per-verb.<br/>
³ — `Ref` rejects `==` at compile time **on purpose**, so accidental comparisons fail loudly.<br/>
⁴ — a fixed set of named types only.<br/>
⁵ — deferred by design, see [Memory zeroization](#memory-zeroization).<br/>
⁶ — `String`/`Int`/… compare by value; `Bytes` and `Decimal` do not.<br/>
⁷ — `rsjethani/secret` stores the secret behind a `*string`, which `fmt` prints as an address,
so its protection is structural even though it also implements `Stringer`/`TextMarshaler`.<br/>
⁸ — `go-secrets` stores the secret behind `func() T` closures, which `fmt` never dereferences.<br/>
⁹ — `go-secrets` marshals the zero value of `T`: redaction exists but is not configurable
and is only meaningful for JSON.<br/>
¹⁰ — `rsjethani/secret` handles `string` only, so genericity and type-preservation are moot.<br/>
¹¹ — `==` compiles but compares the internal `*string` by identity (silently wrong);
its `Equal` helper must be used instead.<br/>
¹² — the value lives in a `func`, and `reflect.DeepEqual` treats non-nil funcs as never equal,
so equal secrets compare unequal.
¹³ — `rsjethani/secret` implements `encoding.TextUnmarshaler` (string only);
`encoding/json` picks it up for string fields, so JSON ingest works for strings,
but there is no generic `json.Unmarshaler`.
¹⁴ — `go-secrets`, `negrel/secrecy`, and `angusgmorrison/logfusc` implement
`json.Unmarshaler` only (no `TextUnmarshaler`), so ingest works for JSON
but not for text-based formats that rely on `TextUnmarshaler`.
¹⁵ — `Ref`/`Handle` do not implement `driver.Valuer` directly:
the secret is exposed to the driver only through the explicit
`ExposeSecretValuer()` wrapper, so the expose is visible at the call site.

The `sensitive` legacy column is the deprecated named types (`String`, `Int`, `Bytes`, …).
They match `go-playground/sensitive` on every interface-based row —
the project began as a fork of it — but add type-preserving redaction.
They still lack the structural protection that makes `Ref`/`Handle` leak-proof,
so prefer those in new code.

`rsjethani/secret` and `andrewbenton/go-secrets` are the two other libraries that
happen to be structurally protected — the former stores a `*string`, the latter a
`func() T`, and `fmt` dereferences neither.
`Ref`/`Handle` differ by combining that protection with correct equality semantics
(`Handle`'s value `==`, `Ref`'s compile-time rejection, and working `reflect.DeepEqual`),
type-preserving redaction, and any element type —
where `rsjethani/secret` is `string`-only with a silently-wrong `==`,
and `go-secrets` breaks `reflect.DeepEqual`.

## Redaction output

By default every `Format<Type>Fn` is a no-op, so secrets print as empty.
Pick a policy at startup:

- `sensitive.Redact()` — replace each secret with a visible, type-preserving
  sentinel (`"REDACTED"`, `NaN`, `math.MinInt*`, `math.MaxUint*`, `0xDEFACE`, …).
- Override an individual `Format<Type>Fn` for custom output (e.g. show the first few characters):

  ```go
  sensitive.FormatStringFn = func(s sensitive.String, f fmt.State, c rune) {
      sensitive.Format(f, c, s.ExposeSecret()[:4]+"…")
  }
  ```

  This also drives `Ref[string]`/`Handle[string]` output,
  since they delegate to the same functions.

- `sensitive.Disable()` — print the real value, for tests only.
  It is a no-op unless the binary name ends in `.test` and `GO_TEST_DISABLE_SENSITIVE` is set,
  minimizing the chance of disabling protection in production.

## Deprecated legacy types

`Bool`, `Bytes`, `Decimal`, `Float32/64`, `Int/8/16/32/64`, `String`, `Uint/8/16/32/64`
are kept only for backward compatibility.
They redact through their `fmt.Formatter` method,
which `fmt` skips the moment it descends through an unexported struct field or a pointer —
the raw secret then leaks.
Prefer `Ref` and `Handle` in new code; if you must keep these, guard them with
[lint-sensitive](https://github.com/powerman/lint-sensitive).

## Memory zeroization

Unlike `negrel/secrecy`, `Ref` and `Handle` do not wipe the secret from memory
via `runtime.SetFinalizer`: finalizers are unreliable here
(strings are immutable, Go moves values in memory, the GC copies).
The right vehicle is the experimental `runtime/secret` package,
and support is deferred until it stabilizes.

## Examples

Runnable programs live in [`_examples/`](_examples/):

- [`basic`](_examples/basic/main.go) — `Ref` with `Redact()`.
- [`custom`](_examples/custom/main.go) — custom redaction via `FormatStringFn`.
- [`handle`](_examples/handle/main.go) — `Handle` value equality and map keys.

---

_Inspired by and started as a fork of
[go-playground/sensitive](https://github.com/go-playground/sensitive)._
