package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_              fmt.Formatter          = (*Uint16)(nil)
	_              json.Marshaler         = (*Uint16)(nil)
	_              encoding.TextMarshaler = (*Uint16)(nil)
	FormatUint16Fn                        = func(_ Uint16, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Uint16 is a sensitive uint16 value.
type Uint16 uint16

// ExposeSecret returns the secret value as a uint16.
func (s Uint16) ExposeSecret() uint16 {
	return uint16(s)
}

func (s Uint16) Format(f fmt.State, c rune) {
	FormatUint16Fn(s, f, c)
}

func (s Uint16) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseUint(string(ss.b), base10, bits16)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint16(v))
}

func (s Uint16) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
