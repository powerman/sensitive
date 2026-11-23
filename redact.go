package sensitive

import (
	"fmt"
	"os"
	"strings"

	"github.com/shopspring/decimal"
)

//nolint:gochecknoinits // Secure-by-default: redaction is the initial policy.
func init() { Redact() }

// Redact sets all Format<type>Fn to output visible, type-preserving values:
//
//	Bool:    false
//	Float*:  123
//	Int*:    123
//	Uint*:   123
//	String:  "REDACTED"
//	Bytes:   0xDEFACE
//	Decimal: 123
//
// The same short number is used for every numeric type on purpose:
// it is easy to spot and to assert in tests,
// and it is exactly representable in any numeric type (int8, float32, decimal).
//
// Redaction is active by default (see package initialization),
// so calling Redact explicitly is optional and idempotent.
// It is useful to restore the default policy after overriding Format<type>Fn or calling Disable.
//
// It overwrites the package-level Format<type>Fn variables without synchronization,
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

// Disable protection of sensitive values.
//
// This is designed to be used only in tests to make it easier to compare
// got/want values. To make Disable actually works it's not enough to just
// call it, there are a couple of extra requirements to minimize a chance
// to get disabled sensitive in production:
//   - Current binary name should have ".test" suffix
//     (or ".test.exe" on Windows).
//   - Environment variable GO_TEST_DISABLE_SENSITIVE should not be empty.
//
// It is recommended to call it from TestMain or non-Parallel tests
// because it is not safe to call from simultaneous goroutines.
//
// Calling Redact after Disable will re-enable protection of sensitive values.
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
