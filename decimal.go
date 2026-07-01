package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/shopspring/decimal"
)

var (
	_               fmt.Formatter          = (*Decimal)(nil)
	_               json.Marshaler         = (*Decimal)(nil)
	_               encoding.TextMarshaler = (*Decimal)(nil)
	FormatDecimalFn                        = func(_ Decimal, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Deprecated: use Ref instead.
type Decimal decimal.Decimal

// ExposeSecret returns the secret value as a decimal.Decimal.
func (s Decimal) ExposeSecret() decimal.Decimal {
	return decimal.Decimal(s)
}

func (s Decimal) Format(f fmt.State, c rune) {
	FormatDecimalFn(s, f, c)
}

func (s Decimal) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseFloat(string(ss.b), bits64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (s Decimal) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
