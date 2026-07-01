package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
)

var (
	_             fmt.Formatter          = (*Bytes)(nil)
	_             json.Marshaler         = (*Bytes)(nil)
	_             encoding.TextMarshaler = (*Bytes)(nil)
	FormatBytesFn                        = func(_ Bytes, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Deprecated: use Ref instead.
type Bytes []byte

// ExposeSecret returns the secret value as a byte slice.
func (s Bytes) ExposeSecret() []byte {
	return []byte(s)
}

func (s Bytes) Format(f fmt.State, c rune) {
	FormatBytesFn(s, f, c)
}

func (s Bytes) MarshalJSON() ([]byte, error) {
	var ss state
	s.Format(&ss, 's')
	return json.Marshal(ss.b)
}

func (s Bytes) MarshalText() (text []byte, err error) {
	var ss state
	s.Format(&ss, 'X')
	return ss.b, nil
}
