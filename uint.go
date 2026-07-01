package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_            fmt.Formatter          = (*Uint)(nil)
	_            json.Marshaler         = (*Uint)(nil)
	_            encoding.TextMarshaler = (*Uint)(nil)
	FormatUintFn                        = func(_ Uint, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Uint is a sensitive uint value.
type Uint uint

// ExposeSecret returns the secret value as a uint.
func (s Uint) ExposeSecret() uint {
	return uint(s)
}

func (s Uint) Format(f fmt.State, c rune) {
	FormatUintFn(s, f, c)
}

func (s Uint) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseUint(string(ss.b), base10, 0)
	if err != nil {
		return nil, err
	}
	return json.Marshal(uint(v))
}

func (s Uint) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
