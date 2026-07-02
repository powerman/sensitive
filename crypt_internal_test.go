package sensitive

import (
	"bytes"
	"testing"

	"github.com/powerman/check"
)

// TestCrypt_storageIsEncrypted verifies that the value stored behind Ref and Handle
// is the ciphertext, not the plaintext — a deep-reflection traversal (as go-spew or
// reflect.DeepEqual would do) cannot reveal the secret.
func TestCrypt_storageIsEncrypted(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("Ref_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		secret := "plaintext-not-stored-in-ref"
		r := New(secret)
		t.NotEqual(**r.pp, secret, "stored value must be ciphertext, not plaintext")
		t.Equal(r.ExposeSecret(), secret, "ExposeSecret must decrypt to original value")
	})

	t.Run("Ref_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		secret := []byte("bytes-not-stored-as-plaintext")
		r := New(secret)
		t.False(bytes.Equal(**r.pp, secret), "stored bytes must be ciphertext, not plaintext")
		t.True(bytes.Equal(r.ExposeSecret(), secret), "ExposeSecret must decrypt to original bytes")
	})

	t.Run("Handle_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		secret := "handle-interned-ciphertext"
		h := Make(secret)
		t.NotEqual(h.h.Value(), secret, "interned value must be ciphertext, not plaintext")
		t.Equal(h.ExposeSecret(), secret, "ExposeSecret must decrypt to original value")
	})
}

// TestCrypt_roundTrip verifies that ExposeSecret correctly decrypts
// arbitrary content including invalid-UTF-8 byte sequences.
func TestCrypt_roundTrip(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("invalid_utf8_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		secret := string([]byte{0xff, 0xfe, 0x00, 0x41})
		r := New(secret)
		t.Equal(r.ExposeSecret(), secret, "invalid-UTF-8 string must round-trip correctly")
	})

	t.Run("invalid_utf8_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		secret := []byte{0xff, 0xfe, 0x00, 0x41}
		r := New(secret)
		t.True(bytes.Equal(r.ExposeSecret(), secret), "invalid-UTF-8 bytes must round-trip correctly")
	})

	t.Run("empty_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		r := New("")
		t.Equal(r.ExposeSecret(), "", "empty string must round-trip correctly")
	})

	t.Run("empty_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		r := New([]byte{})
		got := r.ExposeSecret()
		t.True(bytes.Equal(got, []byte{}), "empty bytes must round-trip to empty")
	})
}

// TestCrypt_determinism verifies that identical plaintexts always produce
// identical ciphertexts within a process, ensuring ==, map keys, and
// reflect.DeepEqual work correctly on the ciphertext.
func TestCrypt_determinism(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("Ref_string_same_ciphertext", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := New("deterministic-secret")
		b := New("deterministic-secret")
		t.Equal(**a.pp, **b.pp, "same plaintext must produce identical ciphertext")
	})

	t.Run("Ref_string_diff_ciphertext", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := New("alpha-value")
		b := New("beta-value")
		t.NotEqual(**a.pp, **b.pp, "different plaintexts must produce different ciphertexts")
	})

	t.Run("Handle_string_equality", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		a := Make("handle-same")
		b := Make("handle-same")
		t.True(a == b, "equal plaintexts must produce equal handles via ciphertext interning")
	})
}

// TestCrypt_nonStringUnchanged verifies that non-string/[]byte types
// are stored as plaintext (no encryption overhead for ints, bools, etc.).
func TestCrypt_nonStringUnchanged(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		r := New(42)
		t.Equal(**r.pp, 42, "int must be stored and returned as-is")
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		r := New(true)
		t.Equal(**r.pp, true, "bool must be stored and returned as-is")
	})

	t.Run("nil_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)

		r := New([]byte(nil))
		t.Nil(**r.pp, "nil []byte must be stored and returned as nil")
		t.Nil(r.ExposeSecret(), "ExposeSecret must return nil for nil input")
	})
}
