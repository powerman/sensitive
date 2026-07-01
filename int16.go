package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_             fmt.Formatter          = (*Int16)(nil)
	_             json.Marshaler         = (*Int16)(nil)
	_             encoding.TextMarshaler = (*Int16)(nil)
	FormatInt16Fn                        = func(_ Int16, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Int16 is a sensitive int16 value.
type Int16 int16

// ExposeSecret returns the secret value as an int16.
func (s Int16) ExposeSecret() int16 {
	return int16(s)
}

func (s Int16) Format(f fmt.State, c rune) {
	FormatInt16Fn(s, f, c)
}

func (s Int16) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseInt(string(ss.b), base10, bits16)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int16(v))
}

func (s Int16) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
