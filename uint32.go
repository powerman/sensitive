package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_              fmt.Formatter          = (*Uint32)(nil)
	_              json.Marshaler         = (*Uint32)(nil)
	_              encoding.TextMarshaler = (*Uint32)(nil)
	FormatUint32Fn                        = func(_ Uint32, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Deprecated: use Handle or Ref instead.
type Uint32 uint32

// ExposeSecret returns the secret value as a uint32.
func (s Uint32) ExposeSecret() uint32 {
	return uint32(s)
}

func (s Uint32) Format(f fmt.State, c rune) {
	FormatUint32Fn(s, f, c)
}

func (s Uint32) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseUint(string(ss.b), base10, bits32)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint32(v))
}

func (s Uint32) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
