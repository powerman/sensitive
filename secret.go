package sensitive

// Secret is an interface implemented
// by both plain sensitive types and Ref[T] and Handle[T],
// allowing them to be used interchangeably.
//
//nolint:iface // This is a public API for users of this package.
type Secret[T any] interface {
	ExposeSecret() T
}
