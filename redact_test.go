package sensitive_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

func ExampleRedact() {
	var (
		vBool    = sensitive.New(true)
		vFloat32 = sensitive.New(float32(4.2))
		vFloat64 = sensitive.New(42.42)
		vInt8    = sensitive.New(int8(-42))
		vInt16   = sensitive.New(int16(-4242))
		vInt32   = sensitive.New(int32(-424242))
		vInt64   = sensitive.New(int64(-42424242))
		vInt     = sensitive.New(-42424242)
		vUint8   = sensitive.New(uint8(42))
		vUint16  = sensitive.New(uint16(4242))
		vUint32  = sensitive.New(uint32(424242))
		vUint64  = sensitive.New(uint64(42424242))
		vUint    = sensitive.New(uint(42424242))
		vString  = sensitive.New("secret")
		vBytes   = sensitive.New([]byte("secret"))
		vDecimal = sensitive.New(decimal.NewFromFloat(42.42))
		vs       = []any{
			vBool, vFloat32, vFloat64,
			vInt8, vInt16, vInt32, vInt64, vInt,
			vUint8, vUint16, vUint32, vUint64, vUint,
			vString, vBytes, vDecimal,
		}
	)

	output := func() {
		fmt.Println(append(append([]any{"fmt.Println(...):"}, vs...), "EOL")...)
		fmt.Printf("fmt.Printf(vs): %v\n", vs)
		json.NewEncoder(os.Stdout).Encode(vs) //nolint:errchkjson // Example test, output verified.
		fmt.Println()
	}
	output()
	sensitive.Redact()
	os.Unsetenv("GO_TEST_DISABLE_SENSITIVE")
	sensitive.Disable()
	output()
	os.Setenv("GO_TEST_DISABLE_SENSITIVE", "1")
	sensitive.Disable()
	output()
	// Output:
	// fmt.Println(...):                 EOL
	// fmt.Printf(vs): [               ]
	// [null,null,null,null,null,null,null,null,null,null,null,null,null,"",null,null]
	//
	// fmt.Println(...): FALSE NaN NaN -128 -32768 -2147483648 -9223372036854775808 -2147483648 255 65535 4294967295 18446744073709551615 4294967295 REDACTED [222 250 206] NaN EOL
	// fmt.Printf(vs): [FALSE NaN NaN -128 -32768 -2147483648 -9223372036854775808 -2147483648 255 65535 4294967295 18446744073709551615 4294967295 REDACTED [222 250 206] NaN]
	// [false,null,null,-128,-32768,-2147483648,-9223372036854775808,-2147483648,255,65535,4294967295,18446744073709551615,4294967295,"REDACTED","3vrO",null]
	//
	// fmt.Println(...): true 4.2 42.42 -42 -4242 -424242 -42424242 -42424242 42 4242 424242 42424242 42424242 secret [115 101 99 114 101 116] 42.42 EOL
	// fmt.Printf(vs): [true 4.2 42.42 -42 -4242 -424242 -42424242 -42424242 42 4242 424242 42424242 42424242 secret [115 101 99 114 101 116] 42.42]
	// [true,4.2,42.42,-42,-4242,-424242,-42424242,-42424242,42,4242,424242,42424242,42424242,"secret","c2VjcmV0",42.42]
}
