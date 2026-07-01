package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_            fmt.Formatter          = (*Int8)(nil)
	_            json.Marshaler         = (*Int8)(nil)
	_            encoding.TextMarshaler = (*Int8)(nil)
	FormatInt8Fn                        = func(_ Int8, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Int8 is a sensitive int8 value.
type Int8 int8

// ExposeSecret returns the secret value as an int8.
func (s Int8) ExposeSecret() int8 {
	return int8(s)
}

func (s Int8) Format(f fmt.State, c rune) {
	FormatInt8Fn(s, f, c)
}

func (s Int8) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseInt(string(ss.b), base10, bits8)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int8(v))
}

func (s Int8) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
