package sensitive

import (
	"fmt"
	"os"
	"strings"

	"github.com/shopspring/decimal"
)

//nolint:gochecknoinits // Secure-by-default: redaction is the initial policy.
func init() { Redact() }

// Redact sets all Format<Type>Fn to output visible values of the original type,
// so JSON output stays valid and log parsers keep working:
//
//	Bool:    false
//	Float*:  123
//	Int*:    123
//	Uint*:   123
//	String:  "REDACTED"
//	Bytes:   0xDEFACE  (DEFACE as text, base64 "3vrO" in JSON)
//	Decimal: 123       (quoted in JSON unless decimal.MarshalJSONWithoutQuotes is set)
//
// All numbers share one short sentinel:
// it is easy to spot and to assert in tests,
// unlike 0 it does not claim a false fact (balance=0),
// and it is exactly representable in any numeric type (int8, float32, decimal).
//
// Redaction is active by default.
// Call Redact to restore it after overriding Format<Type>Fn or calling [Disable].
//
// It overwrites the package-level Format<Type>Fn variables without synchronization,
// so call it only before starting goroutines which use sensitive values
// (e.g. in init or TestMain):
// a concurrent call and any use of those variables is a data race.
func Redact() {
	const sentinel = 123
	FormatBoolFn = func(_ bool, f fmt.State, c rune) { Format(f, c, false) }
	FormatFloat32Fn = func(_ float32, f fmt.State, c rune) { Format(f, c, float32(sentinel)) }
	FormatFloat64Fn = func(_ float64, f fmt.State, c rune) { Format(f, c, float64(sentinel)) }
	FormatInt8Fn = func(_ int8, f fmt.State, c rune) { Format(f, c, int8(sentinel)) }
	FormatInt16Fn = func(_ int16, f fmt.State, c rune) { Format(f, c, int16(sentinel)) }
	FormatInt32Fn = func(_ int32, f fmt.State, c rune) { Format(f, c, int32(sentinel)) }
	FormatInt64Fn = func(_ int64, f fmt.State, c rune) { Format(f, c, int64(sentinel)) }
	FormatIntFn = func(_ int, f fmt.State, c rune) { Format(f, c, int(sentinel)) }
	FormatUint8Fn = func(_ uint8, f fmt.State, c rune) { Format(f, c, uint8(sentinel)) }
	FormatUint16Fn = func(_ uint16, f fmt.State, c rune) { Format(f, c, uint16(sentinel)) }
	FormatUint32Fn = func(_ uint32, f fmt.State, c rune) { Format(f, c, uint32(sentinel)) }
	FormatUint64Fn = func(_ uint64, f fmt.State, c rune) { Format(f, c, uint64(sentinel)) }
	FormatUintFn = func(_ uint, f fmt.State, c rune) { Format(f, c, uint(sentinel)) }
	FormatStringFn = func(_ string, f fmt.State, c rune) { Format(f, c, "REDACTED") }
	FormatBytesFn = func(_ []byte, f fmt.State, c rune) { Format(f, c, []byte{0xDE, 0xFA, 0xCE}) }
	// Decimal does not implement fmt.Formatter, so float verbs would not work on it.
	FormatDecimalFn = func(_ decimal.Decimal, f fmt.State, c rune) { Format(f, c, float64(sentinel)) }
}

// Disable sets all Format<Type>Fn to output the real values.
// It is meant for tests, to make it easier to compare got/want values.
//
// To minimize the chance of disabling protection in production,
// Disable is a no-op unless both conditions hold:
//   - the binary name has the ".test" suffix (or ".test.exe" on Windows);
//   - the environment variable GO_TEST_DISABLE_SENSITIVE is not empty.
//
// It overwrites the package-level Format<Type>Fn variables without synchronization,
// so call it only before starting goroutines which use sensitive values
// (e.g. in TestMain):
// a concurrent call and any use of those variables is a data race.
//
// Call [Redact] to restore protection.
func Disable() {
	name := strings.TrimSuffix(os.Args[0], ".exe")
	if !strings.HasSuffix(name, ".test") || os.Getenv("GO_TEST_DISABLE_SENSITIVE") == "" {
		return
	}
	FormatBoolFn = func(s bool, f fmt.State, c rune) { Format(f, c, s) }
	FormatFloat32Fn = func(s float32, f fmt.State, c rune) { Format(f, c, s) }
	FormatFloat64Fn = func(s float64, f fmt.State, c rune) { Format(f, c, s) }
	FormatInt8Fn = func(s int8, f fmt.State, c rune) { Format(f, c, s) }
	FormatInt16Fn = func(s int16, f fmt.State, c rune) { Format(f, c, s) }
	FormatInt32Fn = func(s int32, f fmt.State, c rune) { Format(f, c, s) }
	FormatInt64Fn = func(s int64, f fmt.State, c rune) { Format(f, c, s) }
	FormatIntFn = func(s int, f fmt.State, c rune) { Format(f, c, s) }
	FormatUint8Fn = func(s uint8, f fmt.State, c rune) { Format(f, c, s) }
	FormatUint16Fn = func(s uint16, f fmt.State, c rune) { Format(f, c, s) }
	FormatUint32Fn = func(s uint32, f fmt.State, c rune) { Format(f, c, s) }
	FormatUint64Fn = func(s uint64, f fmt.State, c rune) { Format(f, c, s) }
	FormatUintFn = func(s uint, f fmt.State, c rune) { Format(f, c, s) }
	FormatStringFn = func(s string, f fmt.State, c rune) { Format(f, c, s) }
	FormatBytesFn = func(s []byte, f fmt.State, c rune) { Format(f, c, s) }
	FormatDecimalFn = func(s decimal.Decimal, f fmt.State, c rune) { Format(f, c, s) }
}
