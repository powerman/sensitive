package sensitive

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/shopspring/decimal"
)

// Redact sets all Format<type>Fn to output visible, non-zero values:
//
//	Bool:    FALSE (in upper case, unlike usual bool)
//	Float*:  NaN
//	Int*:    math.MinInt* (MinInt32 for Int)
//	Uint*:   math.MaxUint* (MaxUint32 for Uint)
//	String:  "REDACTED"
//	Bytes:   0xDEFACE
//	Decimal: NaN
func Redact() {
	FormatBoolFn = func(_ bool, f fmt.State, _ rune) { Format(f, 's', "FALSE") }
	FormatFloat32Fn = func(_ float32, f fmt.State, c rune) { Format(f, c, float32(math.NaN())) }
	FormatFloat64Fn = func(_ float64, f fmt.State, c rune) { Format(f, c, math.NaN()) }
	FormatInt8Fn = func(_ int8, f fmt.State, c rune) { Format(f, c, int8(math.MinInt8)) }
	FormatInt16Fn = func(_ int16, f fmt.State, c rune) { Format(f, c, int16(math.MinInt16)) }
	FormatInt32Fn = func(_ int32, f fmt.State, c rune) { Format(f, c, int32(math.MinInt32)) }
	FormatInt64Fn = func(_ int64, f fmt.State, c rune) { Format(f, c, int64(math.MinInt64)) }
	FormatIntFn = func(_ int, f fmt.State, c rune) { Format(f, c, int(math.MinInt32)) }
	FormatUint8Fn = func(_ uint8, f fmt.State, c rune) { Format(f, c, uint8(math.MaxUint8)) }
	FormatUint16Fn = func(_ uint16, f fmt.State, c rune) { Format(f, c, uint16(math.MaxUint16)) }
	FormatUint32Fn = func(_ uint32, f fmt.State, c rune) { Format(f, c, uint32(math.MaxUint32)) }
	FormatUint64Fn = func(_ uint64, f fmt.State, c rune) { Format(f, c, uint64(math.MaxUint64)) }
	FormatUintFn = func(_ uint, f fmt.State, c rune) { Format(f, c, uint(math.MaxUint32)) }
	FormatStringFn = func(_ string, f fmt.State, c rune) { Format(f, c, "REDACTED") }
	FormatBytesFn = func(_ []byte, f fmt.State, c rune) { Format(f, c, []byte{0xDE, 0xFA, 0xCE}) }
	FormatDecimalFn = func(_ decimal.Decimal, f fmt.State, c rune) { Format(f, c, math.NaN()) }
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
