package sensitive

import "errors"

var (
	errTextSyntax     = errors.New("invalid text input")
	errScanConversion = errors.New("scan type mismatch")
	errUnsupportedT   = errors.New("type unsupported")
)
