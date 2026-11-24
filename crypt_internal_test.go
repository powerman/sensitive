package sensitive

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"strconv"
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

	t.Run("any_int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New[any](42)
		t.Equal(**r.pp, any(42), "interface T holding an int must be stored as is")
	})

	t.Run("nil_bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)

		r := New([]byte(nil))
		t.Nil(r.pp, "nil []byte is a zero value, so it must give the zero Ref")
		t.Nil(r.ExposeSecret(), "ExposeSecret must return nil for nil input")
	})
}

// TestCrypt_anyEncrypted verifies that an interface T holding a string or a byte slice
// is stored as ciphertext and exposed as the original value of the same dynamic type.
func TestCrypt_anyEncrypted(t *testing.T) {
	t.Parallel()

	tests := map[string]any{
		"string":      "secret-in-any",
		"named_str":   namedStr("secret-in-any"),
		"bytes":       []byte("secret-in-any"),
		"named_bytes": namedBytes("secret-in-any"),
	}
	for name, secret := range tests {
		t.Run(name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)

			r := New(secret)
			t.Equal(reflect.TypeOf(**r.pp), reflect.TypeOf(secret), "stored dynamic type")
			t.False(reflect.DeepEqual(**r.pp, secret), "must be stored encrypted")
			t.DeepEqual(r.ExposeSecret(), secret)
		})
	}
}

// TestCrypt_anyBytesCopied verifies that an interface T holding a byte slice
// never shares it with a caller, neither on New nor on ExposeSecret.
func TestCrypt_anyBytesCopied(t *testing.T) {
	t.Parallel()

	tests := map[string]any{
		"bytes":       []byte("secret-in-any"),
		"named_bytes": namedBytes("secret-in-any"),
	}
	for name, secret := range tests {
		t.Run(name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)

			want := bytes.Clone(reflect.ValueOf(secret).Bytes())

			r := New(secret)
			clear(reflect.ValueOf(secret).Bytes())
			exposed := r.ExposeSecret()
			t.DeepEqual(reflect.ValueOf(exposed).Bytes(), want, "New must copy")

			clear(reflect.ValueOf(exposed).Bytes())
			t.DeepEqual(reflect.ValueOf(r.ExposeSecret()).Bytes(), want, "ExposeSecret must copy")
		})
	}
}

// TestCrypt_decryptShort verifies that decrypt returns a copy of input
// when ciphertext is shorter than aes.BlockSize.
func TestCrypt_decryptShort(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	sc := testScratch(t)
	input := []byte{1, 2, 3}
	result := decrypt(sc, input)
	t.DeepEqual(result, []byte{1, 2, 3}, "decrypt of short input must return it unchanged")
	result[0] = 0
	t.DeepEqual(input, []byte{1, 2, 3}, "decrypt of short input must return a copy")
	t.Equal(decrypt(sc, "abc"), "abc")
}

// TestCrypt_deriveKeys verifies that the subkeys come from HKDF-SHA256
// with the versioned info labels and depend on the master key.
func TestCrypt_deriveKeys(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	keys := testKeys()
	master := testMaster()

	wantIV, err := hkdf.Key(sha256.New, master[:], nil, "sensitive:iv-v1", 32)
	t.Nil(err)
	wantAES, err := hkdf.Key(sha256.New, master[:], nil, "sensitive:aes-v1", 32)
	t.Nil(err)
	t.DeepEqual(keys.iv[:], wantIV)
	t.DeepEqual(keys.aes[:], wantAES)
	t.NotEqual(keys.iv, keys.aes)

	master[0]++
	other := deriveKeys(master)
	t.NotEqual(other.iv, keys.iv, "IV key must depend on the master key")
	t.NotEqual(other.aes, keys.aes, "AES key must depend on the master key")
}

// TestCrypt_encrypt verifies that the IV is HMAC-SHA256 with the IV key
// and the body is AES-CTR with the AES key, the same as in stdlib,
// for plaintexts of one block, many blocks and with a partial last block.
func TestCrypt_encrypt(t *testing.T) {
	t.Parallel()

	keys := testKeys()
	for _, size := range []int{0, 1, 16, 17, 31, 32, 33, 64, 100, 127, 128, 129, 1000} {
		t.Run(strconv.Itoa(size), func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)

			plaintext := testRandom(t, size)
			mac := hmac.New(sha256.New, keys.iv[:])
			mac.Write(plaintext)
			iv := mac.Sum(nil)[:aes.BlockSize]
			want := append(slices.Clone(iv), testCTR(t, keys, iv, plaintext)...)

			sc := testScratch(t)
			ct := encrypt(sc, plaintext)
			t.DeepEqual(ct, want, "[]byte")
			t.Equal(encrypt(sc, string(plaintext)), string(want), "string")
			t.DeepEqual(decrypt(sc, ct), plaintext, "[]byte round-trip")
			t.Equal(decrypt(sc, string(ct)), string(plaintext), "string round-trip")
		})
	}
}

// TestCrypt_decrypt verifies that the counter is incremented as in stdlib AES-CTR,
// including a carry over several bytes and a wrap of the whole counter.
func TestCrypt_decrypt(t *testing.T) {
	t.Parallel()

	keys := testKeys()
	ivs := map[string][]byte{
		"zero":     make([]byte, aes.BlockSize),
		"carry1":   append(bytes.Repeat([]byte{0x5a}, aes.BlockSize-1), 0xfe),
		"carry2":   append(bytes.Repeat([]byte{0x5a}, aes.BlockSize-2), 0xfe, 0xff),
		"carry8":   append(bytes.Repeat([]byte{0x5a}, aes.BlockSize-8), bytes.Repeat([]byte{0xff}, 8)...),
		"wrap":     bytes.Repeat([]byte{0xff}, aes.BlockSize),
		"wrapNear": append(bytes.Repeat([]byte{0xff}, aes.BlockSize-1), 0xfd),
	}
	for name, iv := range ivs {
		t.Run(name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)

			body := testRandom(t, 5*aes.BlockSize+7)
			want := testCTR(t, keys, iv, body)
			ct := append(slices.Clone(iv), body...)

			sc := testScratch(t)
			t.DeepEqual(decrypt(sc, ct), want, "[]byte")
			t.Equal(decrypt(sc, string(ct)), string(want), "string")
		})
	}
}

// TestCrypt_wipeScratch verifies that neither a fragment of a plaintext
// nor of its keystream stays reachable from a scratch after use.
func TestCrypt_wipeScratch(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*scratch, []byte){
		"encrypt_bytes":  func(sc *scratch, p []byte) { encrypt(sc, p) },
		"encrypt_string": func(sc *scratch, p []byte) { encrypt(sc, string(p)) },
		"decrypt_bytes":  func(sc *scratch, p []byte) { decrypt(sc, encrypt(sc, p)) },
		"decrypt_string": func(sc *scratch, p []byte) { decrypt(sc, encrypt(sc, string(p))) },
	}
	// Whole blocks, so that the keystream of the last block is known in full:
	// one size for the loop in xorKeyStream and one for the [cipher.NewCTR] path.
	for name, use := range tests {
		for _, blocks := range []int{6, 2 * stdCTRMin / aes.BlockSize} {
			t.Run(fmt.Sprintf("%s/%d", name, blocks), func(tt *testing.T) {
				tt.Parallel()
				t := check.Must(tt)

				keys := testKeys()
				sc := testScratch(t)
				// Use it twice, because some state is saved only on the first Reset.
				for range 2 {
					plaintext := testRandom(t, blocks*aes.BlockSize)
					keystream := encrypt(testScratch(t), plaintext)[aes.BlockSize:]
					for i := range keystream {
						keystream[i] ^= plaintext[i]
					}
					mac := hmac.New(sha256.New, keys.iv[:])
					mac.Write(plaintext)
					macTail := mac.Sum(nil)[aes.BlockSize:] // The first half is the public IV.

					use(sc, plaintext)
					wipeScratch(sc)
					for i := range len(plaintext) - testFragment {
						t.False(reachableContains(sc, plaintext[i:i+testFragment]),
							"plaintext fragment at %d is reachable", i)
						t.False(reachableContains(sc, keystream[i:i+testFragment]),
							"keystream fragment at %d is reachable", i)
					}
					for i := range len(macTail) - testFragment {
						t.False(reachableContains(sc, macTail[i:i+testFragment]),
							"HMAC fragment at %d is reachable", i)
					}
				}
			})
		}
	}
}

// TestCrypt_panicDropsScratch verifies that a scratch used by a panicked call
// is not returned to the pool, because its HMAC state is unknown.
func TestCrypt_panicDropsScratch(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	var used *scratch
	t.Panic(func() {
		crypt("secret", func(sc *scratch, _ string) string {
			used = sc
			sc.mac.Write([]byte("partial plaintext"))
			panic("boom")
		})
	})
	t.NotNil(used)
	for range 100 {
		sc := getScratch()
		t.True(sc != used, "panicked scratch was returned to the pool")
		putScratch(sc)
	}
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

// namedStr is a named type over string, used the same way as [namedBytes].
type namedStr string

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

// namedByte is a named type over byte, so that a slice of it is not a []byte.
type namedByte byte

// TestCrypt_namedByteSliceRoundTrip verifies that a slice of a named byte type
// (not convertible to []byte) is encrypted and round-trips, both directly and inside an interface.
// It used to panic in reflect.Copy.
func TestCrypt_namedByteSliceRoundTrip(tt *testing.T) {
	tt.Parallel()
	t := check.Must(tt)

	input := []namedByte("hello")
	encrypted := encryptT(input)
	t.NotDeepEqual(encrypted, input, "[]namedByte must be encrypted")
	t.DeepEqual(decryptT(encrypted), input, "[]namedByte must decrypt to original value")

	anyInput := any(input)
	anyEncrypted := encryptT(anyInput)
	t.NotDeepEqual(anyEncrypted, anyInput, "[]namedByte in any must be encrypted")
	t.DeepEqual(decryptT(anyEncrypted), anyInput, "[]namedByte in any must decrypt to original value")
}

// testFragment is the length of a fragment which [TestCrypt_wipeScratch] looks for.
// It is long enough to make a false match of random bytes improbable.
const testFragment = 8

func testMaster() [32]byte {
	var master [32]byte
	for i := range master {
		master[i] = byte(i)
	}
	return master
}

func testKeys() cryptoKeys { return deriveKeys(testMaster()) }

func testBlock(t *check.TB, keys cryptoKeys) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(keys.aes[:])
	t.Must(t.Nil(err))
	return block
}

// testScratch returns a new scratch keyed by [testKeys].
func testScratch(t *check.TB) *scratch {
	t.Helper()
	keys := testKeys()
	return newScratch(testBlock(t, keys), keys.iv)
}

// testCTR is a reference AES-CTR implementation.
func testCTR(t *check.TB, keys cryptoKeys, iv, src []byte) []byte {
	t.Helper()
	dst := make([]byte, len(src))
	cipher.NewCTR(testBlock(t, keys), iv).XORKeyStream(dst, src)
	return dst
}

func testRandom(t *check.TB, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	_, err := rand.Read(b)
	t.Must(t.Nil(err))
	return b
}

// reachableContains reports whether any byte array or slice reachable from v contains sub.
func reachableContains(v any, sub []byte) bool {
	return reachableValueContains(reflect.ValueOf(v), sub, make(map[uintptr]bool))
}

func reachableValueContains(v reflect.Value, sub []byte, seen map[uintptr]bool) bool {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return false
		}
		seen[v.Pointer()] = true
		return reachableValueContains(v.Elem(), sub, seen)
	case reflect.Interface:
		return !v.IsNil() && reachableValueContains(v.Elem(), sub, seen)
	case reflect.Struct:
		for _, field := range v.Fields() {
			if reachableValueContains(field, sub, seen) {
				return true
			}
		}
	case reflect.Array, reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range b {
				b[i] = byte(v.Index(i).Uint())
			}
			return bytes.Contains(b, sub)
		}
		for i := range v.Len() {
			if reachableValueContains(v.Index(i), sub, seen) {
				return true
			}
		}
	default:
	}
	return false
}
