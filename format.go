package sensitive

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
)

// Format<type>Fn define how each sensitive type is printed by fmt, marshalers and slog.
// Initially they are set by [Redact] from package init.
// Replace any of them to customize output, or call [Disable] in tests.
//
//nolint:gochecknoglobals // By design.
var (
	FormatBoolFn    func(bool, fmt.State, rune)
	FormatBytesFn   func([]byte, fmt.State, rune)
	FormatDecimalFn func(decimal.Decimal, fmt.State, rune)
	FormatFloat32Fn func(float32, fmt.State, rune)
	FormatFloat64Fn func(float64, fmt.State, rune)
	FormatIntFn     func(int, fmt.State, rune)
	FormatInt8Fn    func(int8, fmt.State, rune)
	FormatInt16Fn   func(int16, fmt.State, rune)
	FormatInt32Fn   func(int32, fmt.State, rune)
	FormatInt64Fn   func(int64, fmt.State, rune)
	FormatStringFn  func(string, fmt.State, rune)
	FormatUintFn    func(uint, fmt.State, rune)
	FormatUint8Fn   func(uint8, fmt.State, rune)
	FormatUint16Fn  func(uint16, fmt.State, rune)
	FormatUint32Fn  func(uint32, fmt.State, rune)
	FormatUint64Fn  func(uint64, fmt.State, rune)
)

// Format outputs value accordingly to formatting options.
//
// It is useful in case you'll redefine some Format<type>Fn to output
// redacted value using formatting applied to original value.
//
//	sensitive.FormatStringFn = func(s string, f fmt.State, c rune) {
//	    sensitive.Format(f, c, "REDACTED")
//	}
//	sensitive.FormatBytesFn = func(s []byte, f fmt.State, c rune) {
//	    sensitive.Format(f, c, []byte{0xDE, 0xFA, 0xCE})
//	}
func Format(f fmt.State, c rune, value any) {
	const flags = "+-# 0"
	const usualLen = 8
	var format strings.Builder
	format.Grow(usualLen)
	format.WriteRune('%')
	for _, c := range flags {
		if f.Flag(int(c)) {
			format.WriteRune(c)
		}
	}
	if wid, ok := f.Width(); ok {
		format.WriteString(strconv.Itoa(wid))
	}
	if prec, ok := f.Precision(); ok {
		format.WriteRune('.')
		format.WriteString(strconv.Itoa(prec))
	}
	format.WriteRune(c)
	_, _ = fmt.Fprintf(f, format.String(), value)
}
