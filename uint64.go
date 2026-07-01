package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_              fmt.Formatter          = (*Uint64)(nil)
	_              json.Marshaler         = (*Uint64)(nil)
	_              encoding.TextMarshaler = (*Uint64)(nil)
	FormatUint64Fn                        = func(_ Uint64, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Deprecated: use Handle or Ref instead.
type Uint64 uint64

// ExposeSecret returns the secret value as a uint64.
func (s Uint64) ExposeSecret() uint64 {
	return uint64(s)
}

func (s Uint64) Format(f fmt.State, c rune) {
	FormatUint64Fn(s, f, c)
}

func (s Uint64) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseUint(string(ss.b), base10, bits64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (s Uint64) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
