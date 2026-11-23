package sensitive_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

type creds struct{ User, Pass string }

// A composite T cannot be redacted by a Format<type>Fn,
// so every egress is nil and none of them breaks the surrounding document.
func TestRef_compositeEgressIsNil(t *testing.T) {
	t.Parallel()
	c := check.T(t)

	type doc struct {
		Name  string               `json:"name"`
		Creds sensitive.Ref[creds] `json:"creds"`
	}
	d := doc{Name: "n", Creds: sensitive.New(creds{User: "u", Pass: "s3cret"})}

	b, err := json.Marshal(d)
	c.Nil(err)
	c.Equal(string(b), `{"name":"n","creds":null}`)

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%10v"} {
		got := fmt.Sprintf(verb, d.Creds)
		c.Equal(strings.TrimSpace(got), "<nil>", verb)
	}
	text, err := d.Creds.MarshalText()
	c.Nil(err)
	c.Equal(string(text), "<nil>")
	c.Equal(fmt.Sprint(d), "{n <nil>}")

	// Ingress and Value stay honest errors: they do not break a foreign document.
	var r sensitive.Ref[creds]
	c.NotNil(r.UnmarshalText([]byte("x")))
	c.NotNil(r.Scan("x"))
	_, err = d.Creds.ExposeSecretValuer().Value()
	c.NotNil(err)
}
