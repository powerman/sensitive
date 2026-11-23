package sensitive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"reflect"
	"sync"
)

// cryptoKeys are the per-process keys derived from one random master key,
// so that each key has exactly one purpose.
type cryptoKeys struct {
	iv  [32]byte // HMAC-SHA256 key to derive the IV from a plaintext.
	aes [32]byte // AES-256 key.
}

// Versioned HKDF info labels: change the version if the way a key is used changes.
const (
	infoIV  = "sensitive:iv-v1"
	infoAES = "sensitive:aes-v1"
)

var (
	cryptoKeysOnce sync.Once  //nolint:gochecknoglobals // Process-scoped keys init guard.
	cryptoKeysVal  cryptoKeys //nolint:gochecknoglobals // Process-scoped keys.
)

func getCryptoKeys() cryptoKeys {
	cryptoKeysOnce.Do(func() {
		var master [32]byte
		_, err := rand.Read(master[:])
		if err != nil {
			panic("sensitive: crypto key init: " + err.Error())
		}
		cryptoKeysVal = deriveKeys(master)
	})
	return cryptoKeysVal
}

func deriveKeys(master [32]byte) cryptoKeys {
	return cryptoKeys{iv: deriveKey(master, infoIV), aes: deriveKey(master, infoAES)}
}

func deriveKey(master [32]byte, info string) [32]byte {
	var key [32]byte
	b, err := hkdf.Key(sha256.New, master[:], nil, info, len(key))
	if err != nil {
		panic("sensitive: HKDF: " + err.Error())
	}
	copy(key[:], b)
	return key
}

// encryptBytes deterministically encrypts plaintext using AES-256-CTR.
// The IV is derived from HMAC-SHA256(keys.iv, plaintext)[:[aes.BlockSize]]
// so identical plaintexts always produce identical ciphertexts within the same process.
// Output layout: IV ([aes.BlockSize] bytes) || CTR-encrypted body.
func encryptBytes(plaintext []byte) []byte {
	keys := getCryptoKeys()

	mac := hmac.New(sha256.New, keys.iv[:])
	mac.Write(plaintext)
	iv := mac.Sum(nil)[:aes.BlockSize]

	block, err := aes.NewCipher(keys.aes[:])
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
	keys := getCryptoKeys()

	block, err := aes.NewCipher(keys.aes[:])
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
	switch rv.Kind() {
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
	switch rv.Kind() {
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
