package sensitive_test

import (
	"testing"

	"github.com/powerman/sensitive"
)

const benchSecret = "sk-live-0123456789abcdef"

var benchSink string

func BenchmarkNew(b *testing.B) {
	for b.Loop() {
		benchSink = sensitive.New(benchSecret).ExposeSecret()
	}
}

func BenchmarkMake(b *testing.B) {
	for b.Loop() {
		benchSink = sensitive.Make(benchSecret).ExposeSecret()
	}
}

func BenchmarkRef_ExposeSecret(b *testing.B) {
	r := sensitive.New(benchSecret)
	for b.Loop() {
		benchSink = r.ExposeSecret()
	}
}

func BenchmarkHandle_ExposeSecret(b *testing.B) {
	h := sensitive.Make(benchSecret)
	for b.Loop() {
		benchSink = h.ExposeSecret()
	}
}
