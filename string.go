package sensitive

import (
	"encoding"
	"encoding/json"
	"fmt"
)

var (
	_              fmt.Formatter          = (*String)(nil)
	_              json.Marshaler         = (*String)(nil)
	_              encoding.TextMarshaler = (*String)(nil)
	FormatStringFn                        = func(_ String, _ fmt.State, _ rune) {} //nolint:gochecknoglobals,godoclint // By design.
)

type String string

// ExposeSecret returns the secret value as a string.
func (s String) ExposeSecret() string {
	return string(s)
}

func (s String) Format(f fmt.State, c rune) {
	FormatStringFn(s, f, c)
}

func (s String) MarshalJSON() ([]byte, error) {
	var ss State
	s.Format(&ss, 'v')
	return json.Marshal(string(ss.b))
}

func (s String) MarshalText() (text []byte, err error) {
	var ss State
	s.Format(&ss, 'v')
	return ss.b, nil
}
