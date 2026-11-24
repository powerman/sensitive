package sensitive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"reflect"
	"sync"
	"unsafe"
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

// scratchPool holds *scratch keyed by the per-process keys.
var scratchPool = sync.OnceValue(func() *sync.Pool { //nolint:gochecknoglobals // Process-scoped keys.
	var master [32]byte
	_, err := rand.Read(master[:])
	if err != nil {
		panic("sensitive: crypto key init: " + err.Error())
	}
	keys := deriveKeys(master)
	block, err := aes.NewCipher(keys.aes[:])
	if err != nil {
		panic("sensitive: AES init: " + err.Error())
	}
	ivKey := keys.iv // Do not capture keys: the AES key is needed only in its expanded form.
	return &sync.Pool{New: func() any { return newScratch(block, ivKey) }}
})

// scratch is the per-call state of encryption and decryption,
// pooled because creating it on every call costs more than the encryption itself.
// The buffers are here because passing a slice to an interface method moves it to the heap.
type scratch struct {
	block cipher.Block
	mac   hash.Hash // Keyed HMAC, always in the Reset state between calls.
	sum   [sha256.Size]byte
	ctr   [aes.BlockSize]byte
	ks    [aes.BlockSize]byte
}

func newScratch(block cipher.Block, ivKey [32]byte) *scratch {
	sc := &scratch{block: block, mac: hmac.New(sha256.New, ivKey[:])}
	// Only a Reset after the first one restores the saved keyed state,
	// overwriting the buffered tail of the previous plaintext.
	sc.mac.Reset()
	return sc
}

func getScratch() *scratch {
	return scratchPool().Get().(*scratch) //nolint:forcetypeassert // Pool holds only *scratch.
}

func putScratch(sc *scratch) {
	wipeScratch(sc)
	scratchPool().Put(sc)
}

// wipeScratch removes what may reveal the last plaintext from sc.
func wipeScratch(sc *scratch) {
	clear(sc.ks[:])
	clear(sc.sum[:]) // Plaintext chunks of a string and the full HMAC, of which only the IV is public.
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

// deriveIV sets sc.ctr to HMAC-SHA256(keys.iv, plaintext)[:[aes.BlockSize]].
// A string plaintext is written through sc.sum to avoid allocating its []byte copy.
func deriveIV[S string | []byte](sc *scratch, plaintext S) {
	if b, ok := any(&plaintext).(*[]byte); ok {
		sc.mac.Write(*b)
	} else {
		for i := 0; i < len(plaintext); i += len(sc.sum) {
			n := copy(sc.sum[:], plaintext[i:])
			sc.mac.Write(sc.sum[:n])
		}
	}
	copy(sc.ctr[:], sc.mac.Sum(sc.sum[:0]))
	sc.mac.Reset() // Also overwrites the buffered tail of plaintext.
}

// stdCTRMin is the length from which [cipher.NewCTR] is faster than the loop in [xorKeyStream]
// despite its per-call allocation.
const stdCTRMin = 128

// xorKeyStream sets dst to src XORed with the AES-CTR keystream,
// with a 128-bit big-endian counter starting at sc.ctr, the same as [cipher.NewCTR].
func xorKeyStream[S string | []byte](sc *scratch, dst []byte, src S) {
	if len(src) >= stdCTRMin {
		copy(dst, src)
		cipher.NewCTR(sc.block, sc.ctr[:]).XORKeyStream(dst, dst)
		return
	}
	for i := 0; i < len(src); i += aes.BlockSize {
		sc.block.Encrypt(sc.ks[:], sc.ctr[:])
		n := min(aes.BlockSize, len(src)-i)
		for j := range n {
			dst[i+j] = src[i+j] ^ sc.ks[j]
		}
		for j := aes.BlockSize - 1; j >= 0; j-- {
			sc.ctr[j]++
			if sc.ctr[j] != 0 {
				break
			}
		}
	}
}

// encrypt deterministically encrypts plaintext using AES-256-CTR.
// The IV is derived from HMAC-SHA256(keys.iv, plaintext)[:[aes.BlockSize]]
// so identical plaintexts always produce identical ciphertexts within the same process.
// Output layout: IV ([aes.BlockSize] bytes) || CTR-encrypted body.
func encrypt[S string | []byte](sc *scratch, plaintext S) S {
	deriveIV(sc, plaintext)
	out := make([]byte, aes.BlockSize+len(plaintext))
	copy(out, sc.ctr[:])
	xorKeyStream(sc, out[aes.BlockSize:], plaintext)
	return bytesAs[S](out)
}

// decrypt decrypts ciphertext produced by [encrypt].
// The result never shares memory with ciphertext,
// so changing it cannot change the stored value.
func decrypt[S string | []byte](sc *scratch, ciphertext S) S {
	if len(ciphertext) < aes.BlockSize {
		// Too short to be our format; return as-is to avoid panic on malformed data.
		return bytesAs[S](append([]byte(nil), ciphertext...))
	}
	copy(sc.ctr[:], ciphertext)
	out := make([]byte, len(ciphertext)-aes.BlockSize)
	xorKeyStream(sc, out, ciphertext[aes.BlockSize:])
	return bytesAs[S](out)
}

// bytesAs returns b as S without copying, so b must not be changed after the call.
func bytesAs[S string | []byte](b []byte) S {
	var s S
	switch p := any(&s).(type) {
	case *string:
		*p = unsafe.String(unsafe.SliceData(b), len(b)) //nolint:gosec // Audited: see the doc comment.
	case *[]byte:
		*p = b
	}
	return s
}

// encryptT returns v encrypted if T is a string or []byte kind (including named types),
// or an interface holding such a value.
// For all other T, v is returned unchanged.
func encryptT[T any](v T) T {
	return cryptT(v, encrypt[string], encrypt[[]byte])
}

// decryptT returns v decrypted if T is a string or []byte kind (including named types),
// or an interface holding such a value.
// For all other T, v is returned unchanged.
func decryptT[T any](v T) T {
	return cryptT(v, decrypt[string], decrypt[[]byte])
}

type (
	cryptString = func(*scratch, string) string
	cryptBytes  = func(*scratch, []byte) []byte
)

func cryptT[T any](v T, fs cryptString, fb cryptBytes) T {
	switch p := any(&v).(type) {
	case *string:
		*p = crypt(*p, fs)
		return v
	case *[]byte:
		if *p != nil {
			*p = crypt(*p, fb)
		}
		return v
	}
	switch reflect.TypeFor[T]().Kind() {
	case reflect.String, reflect.Slice:
		return cryptNamed(v, fs, fb)
	case reflect.Interface:
		return cryptIface(v, fs, fb)
	default:
		return v
	}
}

// cryptIface is the path of [cryptT] for an interface T:
// it crypts a string or a byte slice (including named types) held by v and keeps its dynamic type.
// The result never shares memory with v.
func cryptIface[T any](v T, fs cryptString, fb cryptBytes) T {
	// The common dynamic types are handled without reflect, which is much cheaper.
	switch x := any(v).(type) {
	case string:
		return any(crypt(x, fs)).(T) //nolint:forcetypeassert // T is an interface holding a string.
	case []byte:
		if x == nil {
			return v
		}
		return any(crypt(x, fb)).(T) //nolint:forcetypeassert // T is an interface holding []byte.
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		c := reflect.New(rv.Type()).Elem()
		c.SetString(crypt(rv.String(), fs))
		return c.Interface().(T) //nolint:forcetypeassert // The dynamic type is unchanged.
	case reflect.Slice:
		if rv.Type().Elem().Kind() != reflect.Uint8 || rv.IsNil() {
			return v
		}
		c := reflect.New(rv.Type()).Elem()
		c.SetBytes(crypt(rv.Bytes(), fb))
		return c.Interface().(T) //nolint:forcetypeassert // The dynamic type is unchanged.
	default:
		return v
	}
}

// cryptNamed is the reflect-based path of [cryptT] for named types,
// kept separate so that v does not move to the heap on the fast path.
func cryptNamed[T any](v T, fs cryptString, fb cryptBytes) T {
	rv := reflect.ValueOf(&v).Elem()
	switch rv.Kind() {
	case reflect.String:
		rv.SetString(crypt(rv.String(), fs))
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 && !rv.IsNil() {
			rv.SetBytes(crypt(rv.Bytes(), fb))
		}
	default:
	}
	return v
}

// crypt deliberately does not use defer to return sc to the pool:
// after a panic in f the keyed HMAC may be left in a non-Reset state,
// and such a scratch must be dropped instead of being reused.
func crypt[S string | []byte](v S, f func(*scratch, S) S) S {
	sc := getScratch()
	res := f(sc, v)
	putScratch(sc)
	return res
}
