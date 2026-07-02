# Go package with base types protected from the human eye

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/sensitive?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/sensitive/test.yml?label=test)](https://github.com/powerman/sensitive/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/sensitive/gh-badges/coverage.svg)](https://github.com/powerman/sensitive/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/powerman/sensitive)](https://goreportcard.com/report/github.com/powerman/sensitive)
[![Release](https://img.shields.io/github/v/release/powerman/sensitive?color=blue)](https://github.com/powerman/sensitive/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/sensitive.svg)](https://pkg.go.dev/github.com/powerman/sensitive)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Package sensitive provides base types who's values should never be seen by
the human eye, but still used for configuration.

Sometimes you have a variable, such as a password or an API token,
passed into your program via arguments or ENV variables.
Some of these variables are very sensitive
and should not in any circumstance be logged or sent via JSON
(despite JSON's "-", which people may forget).
These variables, which are just typed primitive types,
implements `fmt.Formatter`, `encoding.TestMarshaler` & `json.Marshaler`.

As an added bonus using them as their base type eg. `String` => `string`, you
have to explicitly cast the eg. `string(s)` This makes you think about what
you're doing and why you casting it providing additional safety.

Supported types:

- `Bool`
- `Bytes`
- `Decimal` from <https://github.com/shopspring/decimal>
- `Float32`
- `Float64`
- `Int`
- `Int8`
- `Int16`
- `Int32`
- `Int64`
- `String` (the most useful)
- `Uint`
- `Uint8`
- `Uint16`
- `Uint32`
- `Uint64`

## Storing secrets in unexported fields

`Bytes`/`String`/etc. redact via `fmt.Formatter`, but this only works
when `fmt` can call `CanInterface() == true` on the value's reflect wrapper.
The moment `fmt` descends through an **unexported struct field**,
`reflect` sets an internal read-only flag (`flagRO`),
`CanInterface()` returns false, and `fmt.Formatter` is skipped —
the raw secret leaks into logs and error messages.

### `Ref[T]` — non-comparable, for any type

`Ref[T]` is a generic wrapper that stores its value
behind **two** pointer indirections (`**T`), which `fmt` never fully follows.
It behaves like `[]byte` for equality: `==` is a compile-time error,
so an accidental comparison fails loudly instead of silently returning false.
Use `Ref` when the element type is not value-comparable (`[]byte`, decimals,
composites) or when value-`==` is harmful (passwords, hashes).

```go
type Config struct {
	apiKey sensitive.Ref[string]    // safe — fmt cannot reach the value
	dbPass sensitive.Ref[[]byte]    // safe, even for compound types
}

k := sensitive.New("sk-...")
key := k.ExposeSecret() // explicit opt-in to access the real value
```

`Ref` is **non-comparable** (`==` is a compile error, not a valid map key).
Use `reflect.DeepEqual` or explicit compare functions for testing.

### `Handle[T]` — comparable, for value-comparable secrets

For value-comparable secrets where `==` is not harmful (tokens, IDs, API keys),
`Handle[T]` provides value equality and map-key support while remaining
fmt-safe. Equal values are canonicalized via the runtime's `unique.Handle`
intern pool.

```go
type AccessToken struct{ sensitive.Handle[string] }

t := sensitive.Make("sk-...")
t == sensitive.Make("sk-...") // true
```

### Safety net

Run [lint-sensitive](https://github.com/powerman/lint-sensitive) as part
of your CI to catch remaining unexported-field leaks.

### Memory zeroization is deferred

Unlike `negrel/secrecy`, `Ref` and `Handle` do not use `runtime.SetFinalizer`:
finalizers are unreliable (strings are immutable, Go moves values in memory, GC copies).
The right vehicle is the experimental `runtime/secret` package.

## Examples

### Basic

```go
// go run _examples/basic/main.go mypassword
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/powerman/sensitive"
)

func main() {
	password := sensitive.String(os.Args[1])

	fmt.Printf("%s\n", password)
	fmt.Printf("%v\n", password)

	b, _ := json.Marshal(password)
	fmt.Println(string(b))

	var empty *sensitive.String
	b, _ = json.Marshal(empty)
	fmt.Println(string(b))

	// output:
	//
	//
	// ""
	// null
}
```

### Custom Formatting

```go
// go run _examples/custom/main.go mypassword
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/powerman/sensitive"
)

func init() {
	// override default Formatter
	sensitive.FormatStringFn = func(s sensitive.String, f fmt.State, c rune) {
		switch c {
		default:
			sensitive.Format(f, c, "redacted")
		case 'v':
			sensitive.Format(f, c, string(s)[:4]+"*******")
		}
	}
}

func main() {
	password := sensitive.String(os.Args[1])

	fmt.Printf("%s\n", password)
	fmt.Printf("%v\n", password)

	b, _ := json.Marshal(password)
	fmt.Println(string(b))

	var empty *sensitive.String
	b, _ = json.Marshal(empty)
	fmt.Println(string(b))

	// output:
	// redacted
	// mypa*******
	// "mypa*******"
	// null
}
```

---

_Inspired by and started as a fork of
[go-playground/sensitive](https://github.com/go-playground/sensitive)._
