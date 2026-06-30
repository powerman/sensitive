package sensitive_test

import (
	"testing"

	"github.com/powerman/check"
	"github.com/shopspring/decimal"

	"github.com/powerman/sensitive"
)

func Test_exposeSecretInterface(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[string] = sensitive.String("plain")
		var boxed sensitive.Secret[string] = sensitive.New("boxed")

		t.Equal(plain.ExposeSecret(), "plain")
		t.Equal(boxed.ExposeSecret(), "boxed")
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[bool] = sensitive.Bool(true)
		var boxed sensitive.Secret[bool] = sensitive.New(true)

		t.Equal(plain.ExposeSecret(), true)
		t.Equal(boxed.ExposeSecret(), true)
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[int] = sensitive.Int(42)
		var boxed sensitive.Secret[int] = sensitive.New(42)

		t.Equal(plain.ExposeSecret(), 42)
		t.Equal(boxed.ExposeSecret(), 42)
	})

	t.Run("int8", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[int8] = sensitive.Int8(42)
		var boxed sensitive.Secret[int8] = sensitive.New(int8(42))

		t.Equal(plain.ExposeSecret(), int8(42))
		t.Equal(boxed.ExposeSecret(), int8(42))
	})

	t.Run("int16", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[int16] = sensitive.Int16(42)
		var boxed sensitive.Secret[int16] = sensitive.New(int16(42))

		t.Equal(plain.ExposeSecret(), int16(42))
		t.Equal(boxed.ExposeSecret(), int16(42))
	})

	t.Run("int32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[int32] = sensitive.Int32(42)
		var boxed sensitive.Secret[int32] = sensitive.New(int32(42))

		t.Equal(plain.ExposeSecret(), int32(42))
		t.Equal(boxed.ExposeSecret(), int32(42))
	})

	t.Run("int64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[int64] = sensitive.Int64(42)
		var boxed sensitive.Secret[int64] = sensitive.New(int64(42))

		t.Equal(plain.ExposeSecret(), int64(42))
		t.Equal(boxed.ExposeSecret(), int64(42))
	})

	t.Run("uint", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[uint] = sensitive.Uint(42)
		var boxed sensitive.Secret[uint] = sensitive.New(uint(42))

		t.Equal(plain.ExposeSecret(), uint(42))
		t.Equal(boxed.ExposeSecret(), uint(42))
	})

	t.Run("uint8", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[uint8] = sensitive.Uint8(42)
		var boxed sensitive.Secret[uint8] = sensitive.New(uint8(42))

		t.Equal(plain.ExposeSecret(), uint8(42))
		t.Equal(boxed.ExposeSecret(), uint8(42))
	})

	t.Run("uint16", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[uint16] = sensitive.Uint16(42)
		var boxed sensitive.Secret[uint16] = sensitive.New(uint16(42))

		t.Equal(plain.ExposeSecret(), uint16(42))
		t.Equal(boxed.ExposeSecret(), uint16(42))
	})

	t.Run("uint32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[uint32] = sensitive.Uint32(42)
		var boxed sensitive.Secret[uint32] = sensitive.New(uint32(42))

		t.Equal(plain.ExposeSecret(), uint32(42))
		t.Equal(boxed.ExposeSecret(), uint32(42))
	})

	t.Run("uint64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[uint64] = sensitive.Uint64(42)
		var boxed sensitive.Secret[uint64] = sensitive.New(uint64(42))

		t.Equal(plain.ExposeSecret(), uint64(42))
		t.Equal(boxed.ExposeSecret(), uint64(42))
	})

	t.Run("float32", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[float32] = sensitive.Float32(3.14)
		var boxed sensitive.Secret[float32] = sensitive.New(float32(3.14))

		t.Equal(plain.ExposeSecret(), float32(3.14))
		t.Equal(boxed.ExposeSecret(), float32(3.14))
	})

	t.Run("float64", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[float64] = sensitive.Float64(2.718)
		var boxed sensitive.Secret[float64] = sensitive.New(2.718)

		t.Equal(plain.ExposeSecret(), 2.718)
		t.Equal(boxed.ExposeSecret(), 2.718)
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		var plain sensitive.Secret[[]byte] = sensitive.Bytes("plain-bytes")
		var boxed sensitive.Secret[[]byte] = sensitive.New([]byte("boxed-bytes"))

		t.Equal(string(plain.ExposeSecret()), "plain-bytes")
		t.Equal(string(boxed.ExposeSecret()), "boxed-bytes")
	})

	t.Run("decimal", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		d := decimal.NewFromFloat(1.5)
		var plain sensitive.Secret[decimal.Decimal] = sensitive.Decimal(d)
		var boxed sensitive.Secret[decimal.Decimal] = sensitive.New(d)

		t.True(plain.ExposeSecret().Equal(d))
		t.True(boxed.ExposeSecret().Equal(d))
	})
}
