package sensitive

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
)

//nolint:gochecknoglobals,godoclint // By design.
var (
	FormatBoolFn    = func(_ bool, _ fmt.State, _ rune) {}
	FormatBytesFn   = func(_ []byte, _ fmt.State, _ rune) {}
	FormatDecimalFn = func(_ decimal.Decimal, _ fmt.State, _ rune) {}
	FormatFloat32Fn = func(_ float32, _ fmt.State, _ rune) {}
	FormatFloat64Fn = func(_ float64, _ fmt.State, _ rune) {}
	FormatIntFn     = func(_ int, _ fmt.State, _ rune) {}
	FormatInt8Fn    = func(_ int8, _ fmt.State, _ rune) {}
	FormatInt16Fn   = func(_ int16, _ fmt.State, _ rune) {}
	FormatInt32Fn   = func(_ int32, _ fmt.State, _ rune) {}
	FormatInt64Fn   = func(_ int64, _ fmt.State, _ rune) {}
	FormatStringFn  = func(_ string, _ fmt.State, _ rune) {}
	FormatUintFn    = func(_ uint, _ fmt.State, _ rune) {}
	FormatUint8Fn   = func(_ uint8, _ fmt.State, _ rune) {}
	FormatUint16Fn  = func(_ uint16, _ fmt.State, _ rune) {}
	FormatUint32Fn  = func(_ uint32, _ fmt.State, _ rune) {}
	FormatUint64Fn  = func(_ uint64, _ fmt.State, _ rune) {}
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
