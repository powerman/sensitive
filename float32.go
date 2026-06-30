package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strconv"
)

var (
	_               fmt.Formatter          = (*Float32)(nil)
	_               json.Marshaler         = (*Float32)(nil)
	_               encoding.TextMarshaler = (*Float32)(nil)
	FormatFloat32Fn                        = func(_ Float32, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

// Float32 is a sensitive float32 value.
type Float32 float32

// ExposeSecret returns the secret value as a float32.
func (s Float32) ExposeSecret() float32 {
	return float32(s)
}

func (s Float32) Format(f fmt.State, c rune) {
	FormatFloat32Fn(s, f, c)
}

func (s Float32) MarshalJSON() ([]byte, error) {
	var ss State
	s.Format(&ss, 'v')
	if len(ss.b) == 0 {
		return json.Marshal(nil)
	}
	v, err := strconv.ParseFloat(string(ss.b), bits32)
	if err != nil {
		return nil, err
	}
	return json.Marshal(float32(v))
}

func (s Float32) MarshalText() (text []byte, err error) {
	var ss State
	s.Format(&ss, 'v')
	return ss.b, nil
}
