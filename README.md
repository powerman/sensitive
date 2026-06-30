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

Sometimes you have a variable, such as a password,
passed into your program via arguments or ENV variables.
Some of these variables are very sensitive
and should not in any circumstance be loggged or sent via JSON,
despite JSON's "-", which people may forget.
These variables, which are just typed primitive types,
have their overridden `fmt.Formatter`, `encoding.MarshalText` & `json.Marshal` implementations.

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

*Inspired by and started as a fork of
[go-playground/sensitive](https://github.com/go-playground/sensitive).*
