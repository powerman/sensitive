package sensitive_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

// jsonTagged holds Ref[string], Ref[[]byte] and Handle[string] fields with
// omitempty and omitzero struct tags for comparison.
//
//nolint:modernize // Intentionally testing omitempty behavior on struct fields.
type jsonTagged struct {
	RefZero   sensitive.Ref[string] `json:"ref_zero,omitempty"`
	RefZeroZ  sensitive.Ref[string] `json:"ref_zeroz,omitzero"`
	RefEmpty  sensitive.Ref[string] `json:"ref_empty,omitempty"`
	RefEmptyZ sensitive.Ref[string] `json:"ref_emptyz,omitzero"`
	RefValue  sensitive.Ref[string] `json:"ref_value,omitempty"`
	RefValueZ sensitive.Ref[string] `json:"ref_valuez,omitzero"`

	RefBytesZero   sensitive.Ref[[]byte] `json:"ref_bytes_zero,omitempty"`
	RefBytesZeroZ  sensitive.Ref[[]byte] `json:"ref_bytes_zeroz,omitzero"`
	RefBytesNil    sensitive.Ref[[]byte] `json:"ref_bytes_nil,omitempty"`
	RefBytesNilZ   sensitive.Ref[[]byte] `json:"ref_bytes_nilz,omitzero"`
	RefBytesEmpty  sensitive.Ref[[]byte] `json:"ref_bytes_empty,omitempty"`
	RefBytesEmptyZ sensitive.Ref[[]byte] `json:"ref_bytes_emptyz,omitzero"`

	HandleZero   sensitive.Handle[string] `json:"handle_zero,omitempty"`
	HandleZeroZ  sensitive.Handle[string] `json:"handle_zeroz,omitzero"`
	HandleEmpty  sensitive.Handle[string] `json:"handle_empty,omitzero"`
	HandleEmptyZ sensitive.Handle[string] `json:"handle_emptyz,omitzero"`
	HandleValue  sensitive.Handle[string] `json:"handle_value,omitzero"`
	HandleValueZ sensitive.Handle[string] `json:"handle_valuez,omitzero"`
}

// fieldInJSON checks whether a JSON key is present in the marshalled output.
func fieldInJSON(data []byte, field string) bool {
	return strings.Contains(string(data), `"`+field+`"`)
}

// fieldNotInJSON checks whether a JSON key is absent from the marshalled output.
func fieldNotInJSON(data []byte, field string) bool {
	return !fieldInJSON(data, field)
}

func TestJSONTags_omitempty_omitzero(t *testing.T) {
	t.Parallel()

	// Expected behavior after adding IsZero() to Ref and Handle:
	//   - omitempty  -> never omits struct fields
	//   - omitzero   -> omits when IsZero() returns true:
	//                   zero value and New("")/Make("")/New(nil)

	t.Run("uninitialized_zero_value", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		var v jsonTagged
		b, err := json.Marshal(v)
		t.Nil(err)

		// omitempty does NOT omit struct fields.
		t.True(fieldInJSON(b, "ref_zero"), "omitempty should not omit zero-value Ref[string]")
		t.True(fieldInJSON(b, "ref_bytes_zero"), "omitempty should not omit zero-value Ref[[]byte]")
		t.True(fieldInJSON(b, "handle_zero"), "omitempty should not omit zero-value Handle[string]")

		// omitzero OMITS zero-value Ref/Handle via IsZero().
		for _, f := range []string{
			"ref_zeroz", "ref_emptyz", "ref_valuez",
			"ref_bytes_zeroz", "ref_bytes_nilz", "ref_bytes_emptyz",
			"handle_zeroz", "handle_emptyz", "handle_value", "handle_valuez",
		} {
			t.True(fieldNotInJSON(b, f), "omitzero should omit zero-value field %s", f)
		}
	})

	t.Run("empty_value_new_make_emptystring", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		v := jsonTagged{
			RefEmpty:     sensitive.New(""),
			RefEmptyZ:    sensitive.New(""),
			HandleEmpty:  sensitive.Make(""),
			HandleEmptyZ: sensitive.Make(""),
		}
		b, err := json.Marshal(v)
		t.Nil(err)

		// omitempty: struct fields are never omitted by omitempty.
		t.True(fieldInJSON(b, "ref_empty"), "omitempty should not omit New(\"\")")

		// omitzero: NOW omits New("")/Make("") because IsZero() returns true.
		t.True(fieldNotInJSON(b, "ref_emptyz"), "omitzero should omit New(\"\") via IsZero()")
		t.True(fieldNotInJSON(b, "handle_empty"), "omitzero should omit Make(\"\") via IsZero()")
		t.True(fieldNotInJSON(b, "handle_emptyz"), "omitzero should omit Make(\"\") via IsZero()")

		// Unset omitempty fields are still present.
		t.True(fieldInJSON(b, "ref_zero"), "omitempty should not omit Ref[string]{}")
		t.True(fieldInJSON(b, "handle_zero"), "omitempty should not omit Handle{}")

		// Unset omitzero fields are omitted.
		t.True(fieldNotInJSON(b, "ref_zeroz"), "omitzero should omit Ref[string]{}")
		t.True(fieldNotInJSON(b, "handle_zeroz"), "omitzero should omit Handle{}")
	})

	t.Run("nonempty_value_new_make_value", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		v := jsonTagged{
			RefValue:     sensitive.New("hello"),
			RefValueZ:    sensitive.New("hello"),
			HandleValue:  sensitive.Make("hello"),
			HandleValueZ: sensitive.Make("hello"),
		}
		b, err := json.Marshal(v)
		t.Nil(err)

		// omitempty: struct fields are always present.
		t.True(fieldInJSON(b, "ref_value"), "omitempty should not omit New(\"hello\")")

		// omitzero: non-zero values are NOT omitted (IsZero() returns false).
		t.True(fieldInJSON(b, "ref_valuez"), "omitzero should NOT omit New(\"hello\") because IsZero() is false")
		t.True(fieldInJSON(b, "handle_value"), "omitzero should NOT omit Make(\"hello\") because IsZero() is false")
		t.True(fieldInJSON(b, "handle_valuez"), "omitzero should NOT omit Make(\"hello\") because IsZero() is false")
	})

	t.Run("ref_bytes_nil", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		v := jsonTagged{
			RefBytesNil:  sensitive.New([]byte(nil)),
			RefBytesNilZ: sensitive.New([]byte(nil)),
		}
		b, err := json.Marshal(v)
		t.Nil(err)

		// omitempty: never omits.
		t.True(fieldInJSON(b, "ref_bytes_nil"), "omitempty should not omit New([]byte(nil))")

		// omitzero: New(nil) stores a nil []byte, ExposeSecret returns nil -> IsZero is true.
		t.True(fieldNotInJSON(b, "ref_bytes_nilz"), "omitzero should omit New([]byte(nil)) via IsZero()")
	})

	t.Run("ref_bytes_empty", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		v := jsonTagged{
			RefBytesEmpty:  sensitive.New([]byte{}),
			RefBytesEmptyZ: sensitive.New([]byte{}),
		}
		b, err := json.Marshal(v)
		t.Nil(err)

		// omitempty: never omits.
		t.True(fieldInJSON(b, "ref_bytes_empty"), "omitempty should not omit New([]byte{})")

		// omitzero: New([]byte{}) stores an encrypted empty body that decrypts to
		// a non-nil empty []byte, and reflect.Value.IsZero() for slices checks IsNil() -> IsZero is false.
		t.True(fieldInJSON(b, "ref_bytes_emptyz"), "omitzero should NOT omit New([]byte{}) because IsZero() is false")
	})
}
