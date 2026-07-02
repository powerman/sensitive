package sensitive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"reflect"
	"sync"
)

var (
	cryptoKeyOnce sync.Once //nolint:gochecknoglobals // Process-scoped key init guard.
	cryptoKey     [32]byte  //nolint:gochecknoglobals // Process-scoped AES-256 key.
)

func getCryptoKey() [32]byte {
	cryptoKeyOnce.Do(func() {
		_, err := rand.Read(cryptoKey[:])
		if err != nil {
			panic("sensitive: crypto key init: " + err.Error())
		}
	})
	return cryptoKey
}

// encryptBytes deterministically encrypts plaintext using AES-256-CTR.
// The IV is derived from HMAC-SHA256(key, plaintext)[:[aes.BlockSize]]
// so identical plaintexts always produce identical ciphertexts within the same process.
// Output layout: IV ([aes.BlockSize] bytes) || CTR-encrypted body.
func encryptBytes(plaintext []byte) []byte {
	key := getCryptoKey()

	mac := hmac.New(sha256.New, key[:])
	mac.Write(plaintext)
	iv := mac.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("sensitive: AES init: " + err.Error())
	}

	out := make([]byte, aes.BlockSize+len(plaintext))
	copy(out, iv)
	cipher.NewCTR(block, iv).XORKeyStream(out[aes.BlockSize:], plaintext)
	return out
}

// decryptBytes decrypts ciphertext produced by [encryptBytes].
// The first [aes.BlockSize] bytes are the IV; the rest is the CTR-encrypted body.
func decryptBytes(ciphertext []byte) []byte {
	if len(ciphertext) < aes.BlockSize {
		// Too short to be our format; return as-is to avoid panic on malformed data.
		return ciphertext
	}
	key := getCryptoKey()

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("sensitive: AES init: " + err.Error())
	}

	body := ciphertext[aes.BlockSize:]
	out := make([]byte, len(body))
	cipher.NewCTR(block, ciphertext[:aes.BlockSize]).XORKeyStream(out, body)
	return out
}

// encryptT returns v encrypted if T is a string or []byte kind (including named types).
// For all other T, v is returned unchanged.
func encryptT[T any](v T) T {
	rv := reflect.ValueOf(v)
	switch rv.Kind() { //nolint:exhaustive // Only string and []byte kinds are encrypted; all others pass through unchanged.
	case reflect.String:
		result := reflect.New(rv.Type()).Elem()
		result.SetString(string(encryptBytes([]byte(rv.String()))))
		return result.Interface().(T)
	case reflect.Slice:
		if rv.IsNil() || rv.Type().Elem().Kind() != reflect.Uint8 {
			return v
		}
		ct := encryptBytes(rv.Bytes())
		result := reflect.MakeSlice(rv.Type(), len(ct), len(ct))
		reflect.Copy(result, reflect.ValueOf(ct))
		return result.Interface().(T)
	default:
		return v
	}
}

// decryptT returns v decrypted if T is a string or []byte kind (including named types).
// For all other T, v is returned unchanged.
func decryptT[T any](v T) T {
	rv := reflect.ValueOf(v)
	switch rv.Kind() { //nolint:exhaustive // Only string and []byte kinds are decrypted; all others pass through unchanged.
	case reflect.String:
		result := reflect.New(rv.Type()).Elem()
		result.SetString(string(decryptBytes([]byte(rv.String()))))
		return result.Interface().(T)
	case reflect.Slice:
		if rv.IsNil() || rv.Type().Elem().Kind() != reflect.Uint8 {
			return v
		}
		pt := decryptBytes(rv.Bytes())
		result := reflect.MakeSlice(rv.Type(), len(pt), len(pt))
		reflect.Copy(result, reflect.ValueOf(pt))
		return result.Interface().(T)
	default:
		return v
	}
}
