package sensitive

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/powerman/check"
)

// TestCrypt_storageIsEncrypted verifies that the value stored behind Ref and Handle
// is the ciphertext, not the plaintext — a deep-reflection traversal (as go-spew or
// reflect.DeepEqual would do) cannot reveal the secret.
func TestCrypt_storageIsEncrypted(t *testing.T) {
	t.Parallel()

	t.Run("Ref_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		secret := "plaintext-not-stored-in-ref"
		r := New(secret)
		t.NotEqual(**r.pp, secret, "stored value must be ciphertext, not plaintext")
		t.Equal(r.ExposeSecret(), secret, "ExposeSecret must decrypt to original value")
	})

	t.Run("Ref_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		secret := []byte("bytes-not-stored-as-plaintext")
		r := New(secret)
		t.False(bytes.Equal(**r.pp, secret), "stored bytes must be ciphertext, not plaintext")
		t.True(bytes.Equal(r.ExposeSecret(), secret), "ExposeSecret must decrypt to original bytes")
	})

	t.Run("Handle_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		secret := "handle-interned-ciphertext"
		h := Make(secret)
		t.NotEqual(h.h.Value(), secret, "interned value must be ciphertext, not plaintext")
		t.Equal(h.ExposeSecret(), secret, "ExposeSecret must decrypt to original value")
	})
}

// TestCrypt_roundTrip verifies that ExposeSecret correctly decrypts
// arbitrary content including invalid-UTF-8 byte sequences.
func TestCrypt_roundTrip(t *testing.T) {
	t.Parallel()

	t.Run("invalid_utf8_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		secret := string([]byte{0xff, 0xfe, 0x00, 0x41})
		r := New(secret)
		t.Equal(r.ExposeSecret(), secret, "invalid-UTF-8 string must round-trip correctly")
	})

	t.Run("invalid_utf8_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		secret := []byte{0xff, 0xfe, 0x00, 0x41}
		r := New(secret)
		t.True(bytes.Equal(r.ExposeSecret(), secret), "invalid-UTF-8 bytes must round-trip correctly")
	})

	t.Run("empty_string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New("")
		t.Equal(r.ExposeSecret(), "", "empty string must round-trip correctly")
	})

	t.Run("empty_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New([]byte{})
		got := r.ExposeSecret()
		t.True(bytes.Equal(got, []byte{}), "empty bytes must round-trip to empty")
	})
}

// TestCrypt_determinism verifies that identical plaintexts always produce
// identical ciphertexts within a process, ensuring ==, map keys, and
// reflect.DeepEqual work correctly on the ciphertext.
func TestCrypt_determinism(t *testing.T) {
	t.Parallel()

	t.Run("Ref_string_same_ciphertext", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		a := New("deterministic-secret")
		b := New("deterministic-secret")
		t.Equal(**a.pp, **b.pp, "same plaintext must produce identical ciphertext")
	})

	t.Run("Ref_string_diff_ciphertext", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		a := New("alpha-value")
		b := New("beta-value")
		t.NotEqual(**a.pp, **b.pp, "different plaintexts must produce different ciphertexts")
	})

	t.Run("Handle_string_equality", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		a := Make("handle-same")
		b := Make("handle-same")
		t.True(a == b, "equal plaintexts must produce equal handles via ciphertext interning")
	})
}

// TestCrypt_nonStringUnchanged verifies that non-string/[]byte types
// are stored as plaintext (no encryption overhead for ints, bools, etc.).
func TestCrypt_nonStringUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New(42)
		t.Equal(**r.pp, 42, "int must be stored and returned as-is")
	})

	t.Run("bool", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New(true)
		t.Equal(**r.pp, true, "bool must be stored and returned as-is")
	})

	t.Run("nil_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New([]byte(nil))
		t.Nil(**r.pp, "nil []byte must be stored and returned as nil")
		t.Nil(r.ExposeSecret(), "ExposeSecret must return nil for nil input")
	})
}

// TestCrypt_decryptBytesShort verifies that decryptBytes returns input
// unchanged when ciphertext is shorter than aes.BlockSize.
func TestCrypt_decryptBytesShort(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	input := []byte{1, 2, 3}
	result := decryptBytes(input)
	t.True(bytes.Equal(result, input), "decryptBytes of short input must return it unchanged")
}

// TestCrypt_getCryptoKey verifies that getCryptoKey returns a 32-byte key.
func TestCrypt_getCryptoKey(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	key := getCryptoKey()
	t.NotPanic(func() { _ = key[0] }, "crypto key must be accessible")
	t.Equal(len(key), 32, "crypto key must be 32 bytes")
}

// TestCrypt_nonUint8Slice verifies that encryptT/decryptT pass through
// a non-uint8 slice ([]int) unchanged.
func TestCrypt_nonUint8Slice(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	input := []int{1, 2, 3}
	encrypted := encryptT(input)
	t.True(reflect.DeepEqual(encrypted, input), "encryptT must pass through non-uint8 slice unchanged")

	decrypted := decryptT(encrypted)
	t.True(reflect.DeepEqual(decrypted, input), "decryptT must return non-uint8 slice unchanged")
}

// namedBytes is a named type over []byte, used to test that
// encryptT/decryptT work correctly with named byte slice types.
type namedBytes []byte

// TestCrypt_namedBytesRoundTrip verifies that a named []byte type
// round-trips through encryptT+decryptT correctly.
func TestCrypt_namedBytesRoundTrip(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	input := namedBytes("hello")
	encrypted := encryptT(input)
	t.NotEqual(string(encrypted), "hello", "named []byte must be encrypted")

	decrypted := decryptT(encrypted)
	t.Equal(string(decrypted), "hello", "named []byte must decrypt to original value")
}
