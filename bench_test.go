package sensitive_test

import (
	"strings"
	"testing"

	"github.com/powerman/sensitive"
)

// Secrets of typical sizes, short ones are strings and long ones are []byte.
var (
	benchPassword  = strings.Repeat("p", 16)
	benchAPIKey    = strings.Repeat("k", 40)
	benchECKeyPEM  = []byte(strings.Repeat("e", 241))  // PKCS #8 PEM of a P-256 private key.
	benchRSAKeyPEM = []byte(strings.Repeat("r", 1704)) // PKCS #8 PEM of an RSA-2048 private key.
)

var (
	benchSink      string
	benchSinkBytes []byte
	benchSinkAny   any
)

func BenchmarkNew(b *testing.B) {
	b.Run("Password", func(b *testing.B) { benchNew(b, benchPassword, &benchSink) })
	b.Run("APIKey", func(b *testing.B) { benchNew(b, benchAPIKey, &benchSink) })
	b.Run("ECKeyPEM", func(b *testing.B) { benchNew(b, benchECKeyPEM, &benchSinkBytes) })
	b.Run("RSAKeyPEM", func(b *testing.B) { benchNew(b, benchRSAKeyPEM, &benchSinkBytes) })
	b.Run("AnyPassword", func(b *testing.B) { benchNew[any](b, benchPassword, &benchSinkAny) })
	b.Run("AnyECKeyPEM", func(b *testing.B) { benchNew[any](b, benchECKeyPEM, &benchSinkAny) })
	b.Run("AnyRSAKeyPEM", func(b *testing.B) { benchNew[any](b, benchRSAKeyPEM, &benchSinkAny) })
}

func benchNew[T any](b *testing.B, secret T, sink *T) {
	b.Helper()
	for b.Loop() {
		*sink = sensitive.New(secret).ExposeSecret()
	}
}

func BenchmarkMake(b *testing.B) {
	b.Run("Password", func(b *testing.B) { benchMake(b, benchPassword) })
	b.Run("APIKey", func(b *testing.B) { benchMake(b, benchAPIKey) })
}

func benchMake(b *testing.B, secret string) {
	b.Helper()
	for b.Loop() {
		benchSink = sensitive.Make(secret).ExposeSecret()
	}
}

func BenchmarkRef_ExposeSecret(b *testing.B) {
	b.Run("Password", func(b *testing.B) { benchRefExposeSecret(b, benchPassword, &benchSink) })
	b.Run("APIKey", func(b *testing.B) { benchRefExposeSecret(b, benchAPIKey, &benchSink) })
	b.Run("ECKeyPEM", func(b *testing.B) { benchRefExposeSecret(b, benchECKeyPEM, &benchSinkBytes) })
	b.Run("RSAKeyPEM", func(b *testing.B) { benchRefExposeSecret(b, benchRSAKeyPEM, &benchSinkBytes) })
	b.Run("AnyPassword", func(b *testing.B) { benchRefExposeSecret[any](b, benchPassword, &benchSinkAny) })
	b.Run("AnyECKeyPEM", func(b *testing.B) { benchRefExposeSecret[any](b, benchECKeyPEM, &benchSinkAny) })
	b.Run("AnyRSAKeyPEM", func(b *testing.B) { benchRefExposeSecret[any](b, benchRSAKeyPEM, &benchSinkAny) })
}

func benchRefExposeSecret[T any](b *testing.B, secret T, sink *T) {
	b.Helper()
	r := sensitive.New(secret)
	for b.Loop() {
		*sink = r.ExposeSecret()
	}
}

func BenchmarkHandle_ExposeSecret(b *testing.B) {
	b.Run("Password", func(b *testing.B) { benchHandleExposeSecret(b, benchPassword) })
	b.Run("APIKey", func(b *testing.B) { benchHandleExposeSecret(b, benchAPIKey) })
}

func benchHandleExposeSecret(b *testing.B, secret string) {
	b.Helper()
	h := sensitive.Make(secret)
	for b.Loop() {
		benchSink = h.ExposeSecret()
	}
}
