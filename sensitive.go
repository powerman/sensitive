package sensitive

import "fmt"

const (
	base10 = 10
	bits8  = 8
	bits16 = 16
	bits32 = 32
	bits64 = 64
)

var _ fmt.State = (*State)(nil)

// State implements [fmt.State].
type State struct {
	b []byte
}

// Write implements [fmt.State].
func (s *State) Write(b []byte) (n int, err error) {
	s.b = append(s.b, b...)
	return len(b), nil
}

// Width implements [fmt.State].
func (*State) Width() (wid int, ok bool) {
	return 0, false
}

// Precision implements [fmt.State].
func (*State) Precision() (prec int, ok bool) {
	return 0, false
}

// Flag implements [fmt.State].
func (*State) Flag(_ int) bool {
	return false
}
