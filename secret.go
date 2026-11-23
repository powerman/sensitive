package sensitive

// Secret is implemented by [Ref] and [Handle],
// allowing them to be used interchangeably.
//
//nolint:iface // This is a public API for users of this package.
type Secret[T any] interface {
	ExposeSecret() T
}
