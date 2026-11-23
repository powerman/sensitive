package sensitive_test

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

type (
	namedToken string
	namedCount int
	namedFlag  bool
	namedRatio float64
	namedSmall uint8
	namedBlob  []byte
)

func TestNamed_Ref(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		plain slog.LogValuer
		fmt   string
		text  string
		json  string
	}{
		{"string", sensitive.New(namedToken("s3cret")), sensitive.New("s3cret"), `REDACTED`, `REDACTED`, `"REDACTED"`},
		{"int", sensitive.New(namedCount(42)), sensitive.New(42), `123`, `123`, `123`},
		{"bool", sensitive.New(namedFlag(true)), sensitive.New(true), `false`, `false`, `false`},
		{"float64", sensitive.New(namedRatio(0.5)), sensitive.New(0.5), `123`, `123`, `123`},
		{"uint8", sensitive.New(namedSmall(42)), sensitive.New(uint8(42)), `123`, `123`, `123`},
		{"bytes", sensitive.New(namedBlob("s3cret")), sensitive.New([]byte("s3cret")), `[222 250 206]`, `DEFACE`, `"3vrO"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			t.Equal(fmt.Sprintf("%v", tc.value), tc.fmt)
			b, err := json.Marshal(tc.value)
			t.Nil(err)
			t.Equal(string(b), tc.json)
			tm, ok := tc.value.(interface{ MarshalText() ([]byte, error) })
			t.True(ok)
			text, err := tm.MarshalText()
			t.Nil(err)
			t.Equal(string(text), tc.text)
			lv, ok := tc.value.(slog.LogValuer)
			t.True(ok)
			t.Equal(lv.LogValue().Kind(), tc.plain.LogValue().Kind(), "named type must log like its base type")
		})
	}
}

func TestNamed_Handle(t *testing.T) {
	t.Parallel()

	t.Run("redacted", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		h := sensitive.Make(namedToken("s3cret"))
		t.Equal(fmt.Sprintf("%v", h), "REDACTED")
		b, err := json.Marshal(h)
		t.Nil(err)
		t.Equal(string(b), `"REDACTED"`)
		t.True(h == sensitive.Make(namedToken("s3cret")))
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		h := sensitive.Make(namedCount(42))
		t.Equal(fmt.Sprintf("%v", h), "123")
		b, err := json.Marshal(h)
		t.Nil(err)
		t.Equal(string(b), "123")
	})
}

func TestNamed_ingress(t *testing.T) {
	t.Parallel()

	t.Run("Ref.UnmarshalText", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var s sensitive.Ref[namedToken]
		t.Nil(s.UnmarshalText([]byte("abc")))
		t.Equal(s.ExposeSecret(), namedToken("abc"))
		var n sensitive.Ref[namedCount]
		t.Nil(n.UnmarshalText([]byte("42")))
		t.Equal(n.ExposeSecret(), namedCount(42))
		var f sensitive.Ref[namedFlag]
		t.Nil(f.UnmarshalText([]byte("true")))
		t.Equal(f.ExposeSecret(), namedFlag(true))
		var b sensitive.Ref[namedBlob]
		t.Nil(b.UnmarshalText([]byte("abc")))
		t.DeepEqual(b.ExposeSecret(), namedBlob("abc"))
	})

	t.Run("Ref.UnmarshalText_error_hides_input", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var n sensitive.Ref[namedCount]
		err := n.UnmarshalText([]byte("s3cret"))
		t.NotNil(err)
		t.NotContains(err.Error(), "s3cret")
	})

	t.Run("Ref.Scan", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var s sensitive.Ref[namedToken]
		t.Nil(s.Scan([]byte("abc")))
		t.Equal(s.ExposeSecret(), namedToken("abc"))
		var n sensitive.Ref[namedCount]
		t.Nil(n.Scan(int64(42)))
		t.Equal(n.ExposeSecret(), namedCount(42))
		var r sensitive.Ref[namedRatio]
		t.Nil(r.Scan(0.5))
		t.Equal(r.ExposeSecret(), namedRatio(0.5))
		t.NotNil(r.Scan("x"))
	})

	t.Run("Handle", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var s sensitive.Handle[namedToken]
		t.Nil(s.UnmarshalText([]byte("abc")))
		t.Equal(s.ExposeSecret(), namedToken("abc"))
		var n sensitive.Handle[namedCount]
		t.Nil(n.Scan(int64(42)))
		t.Equal(n.ExposeSecret(), namedCount(42))
	})
}

func TestNamed_SecretValuer(t *testing.T) {
	t.Parallel()

	t.Run("string", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(namedToken("s3cret")).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, "s3cret")
		text, err := sv.MarshalText()
		t.Nil(err)
		t.Equal(string(text), "s3cret")
	})

	t.Run("int", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.Make(namedCount(42)).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.Equal(v, int64(42))
		text, err := sv.MarshalText()
		t.Nil(err)
		t.Equal(string(text), "42")
	})

	t.Run("bytes", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		sv := sensitive.New(namedBlob("s3cret")).ExposeSecretValuer()
		v, err := sv.Value()
		t.Nil(err)
		t.DeepEqual(v, []byte("s3cret"))
	})
}
