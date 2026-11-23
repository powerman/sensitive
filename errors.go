package sensitive

import "errors"

var (
	// ErrTextSyntax is wrapped by the error which UnmarshalText and UnmarshalJSON
	// of [Ref] and [Handle] return when the input is not a valid value of the target type.
	// The error never contains the input, because the input may be a secret.
	ErrTextSyntax = errors.New("invalid text input")
	// ErrScanConversion is wrapped by the error which Scan of [Ref] and [Handle] returns
	// when the source value has a type which cannot be stored into the target type.
	ErrScanConversion = errors.New("scan type mismatch")

	errUnsupportedT = errors.New("type unsupported")
)
