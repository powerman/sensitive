package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_             fmt.Formatter          = (*Int32)(nil)
	_             json.Marshaler         = (*Int32)(nil)
	_             encoding.TextMarshaler = (*Int32)(nil)
	FormatInt32Fn                        = func(_ Int32, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Deprecated: use Handle or Ref instead.
type Int32 int32

// ExposeSecret returns the secret value as an int32.
func (s Int32) ExposeSecret() int32 {
	return int32(s)
}

func (s Int32) Format(f fmt.State, c rune) {
	FormatInt32Fn(s, f, c)
}

func (s Int32) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseInt(string(ss.b), base10, bits32)
	if err != nil {
		return nil, err
	}
	return json.Marshal(int32(v))
}

func (s Int32) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'v')
	return ss.b, nil
}
