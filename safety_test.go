package sensitive_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/sensitive"
)

const safetySecret = "SECRET"

// --- Fixture types for the shape matrix ---

type (
	safetyH struct{ H sensitive.Handle[string] }
	safetyR struct{ R sensitive.Ref[string] }
)

type (
	safetyHiddenH struct{ h sensitive.Handle[string] }
	safetyHiddenR struct{ r sensitive.Ref[string] }
)

type (
	safetyInnerExpH struct{ H sensitive.Handle[string] }
	safetyInnerExpR struct{ R sensitive.Ref[string] }
	safetyNestH     struct{ un safetyInnerExpH }
	safetyNestR     struct{ un safetyInnerExpR }
)

type (
	safetyInnerPtrH struct{ H sensitive.Handle[string] }
	safetyInnerPtrR struct{ R sensitive.Ref[string] }
	safetyWhPtrH    struct{ T *safetyInnerPtrH }
	safetyWhPtrR    struct{ T *safetyInnerPtrR }
)

// --- Control types proving the WrapT leak is real ---

// safetyCtrlSec holds an exported sensitive.String field.
// sensitive.String is a Formatter (value receiver),
// but *safetyCtrlSec is NOT a Formatter.
// Under "bad verbs" (%s/%q) fmt skips Format on the
// String field reached through this non-Formatter pointer,
// causing the secret to leak.
type (
	safetyCtrlSec   struct{ secret sensitive.String }
	safetyCtrlWrapT struct{ T *safetyCtrlSec }
)

// TestSafety_noLeak is the main regression matrix:
// 10 container shapes × {Handle, Ref (minus map-key)} × {fmt, json, xml, slog}.
// Every assertion checks the secret is absent; expectAddr shapes additionally
// verify that the structural backstop (an 0x address) fires.
func TestSafety_noLeak(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := safetySecret

	ptrH := sensitive.Make(secret)
	ptrR := sensitive.New(secret)

	type shape struct {
		name       string
		handleVal  any
		refVal     any
		expectAddr bool
		skipXML    bool
	}
	shapes := []shape{
		{
			name:      "value",
			handleVal: sensitive.Make(secret),
			refVal:    sensitive.New(secret),
		},
		{
			name:      "exported",
			handleVal: safetyH{H: sensitive.Make(secret)},
			refVal:    safetyR{R: sensitive.New(secret)},
		},
		{
			name:       "unexported",
			handleVal:  safetyHiddenH{h: sensitive.Make(secret)},
			refVal:     safetyHiddenR{r: sensitive.New(secret)},
			expectAddr: true,
		},
		{
			name:       "nested",
			handleVal:  safetyNestH{un: safetyInnerExpH{H: sensitive.Make(secret)}},
			refVal:     safetyNestR{un: safetyInnerExpR{R: sensitive.New(secret)}},
			expectAddr: true,
		},
		{
			name: "mapkey",
			handleVal: map[sensitive.Handle[string]]sensitive.Handle[string]{
				sensitive.Make(secret): sensitive.Make(secret),
			},
			skipXML: true,
		},
		{
			name:      "mapval",
			handleVal: map[string]sensitive.Handle[string]{"k": sensitive.Make(secret)},
			refVal:    map[string]sensitive.Ref[string]{"k": sensitive.New(secret)},
			skipXML:   true,
		},
		{
			name:      "slice",
			handleVal: []sensitive.Handle[string]{sensitive.Make(secret)},
			refVal:    []sensitive.Ref[string]{sensitive.New(secret)},
			skipXML:   true,
		},
		{
			name:      "array",
			handleVal: [1]sensitive.Handle[string]{sensitive.Make(secret)},
			refVal:    [1]sensitive.Ref[string]{sensitive.New(secret)},
			skipXML:   true,
		},
		{
			name:      "ptr",
			handleVal: &ptrH,
			refVal:    &ptrR,
		},
		{
			name:       "wrapt",
			handleVal:  safetyWhPtrH{T: &safetyInnerPtrH{H: sensitive.Make(secret)}},
			refVal:     safetyWhPtrR{T: &safetyInnerPtrR{R: sensitive.New(secret)}},
			expectAddr: true,
		},
	}

	fmtVerbs := []string{"%v", "%s", "%q", "%+v", "%#v", "%x", "%X"}

	type sink struct {
		name string
		run  func(any) string
	}
	sinks := []sink{
		{
			name: "fmt",
			run: func(a any) string {
				parts := make([]string, 0, len(fmtVerbs))
				for _, verb := range fmtVerbs {
					parts = append(parts, fmt.Sprintf(verb, a))
				}
				return strings.Join(parts, " | ")
			},
		},
		{
			name: "json",
			run: func(a any) string {
				b, err := json.Marshal(a)
				if err != nil {
					return fmt.Sprintf("<json error: %v>", err)
				}
				return string(b)
			},
		},
		{
			name: "xml",
			run: func(a any) string {
				b, err := xml.Marshal(a)
				if err != nil {
					return fmt.Sprintf("<xml error: %v>", err)
				}
				return string(b)
			},
		},
		{
			name: "slog",
			run: func(a any) string {
				var buf bytes.Buffer
				slog.New(slog.NewTextHandler(&buf, nil)).Info("Msg", "k", a)
				return buf.String()
			},
		},
	}

	for _, c := range shapes {
		for _, variant := range []struct {
			name string
			v    any
		}{
			{"Handle", c.handleVal},
			{"Ref", c.refVal},
		} {
			if variant.v == nil {
				continue
			}
			for _, s := range sinks {
				if s.name == "xml" && c.skipXML {
					continue
				}

				t.Run(c.name+"/"+variant.name+"/"+s.name, func(tt *testing.T) {
					tt.Parallel()
					t := check.T(tt)

					out := s.run(variant.v)

					t.NotContains(out, secret,
						"%s/%s/%s must not leak secret", c.name, variant.name, s.name)

					// Guard against vacuous passes from swallowed marshal errors:
					// an unexpected json/xml error would otherwise leave the output
					// secret-free but untested. The shapes that legitimately error
					// are skipped via skipJSON/skipXML, so any error here is a bug.
					if s.name == "json" {
						t.NotContains(out, "<json error",
							"%s/%s/json must not error", c.name, variant.name)
					}
					if s.name == "xml" {
						t.NotContains(out, "<xml error",
							"%s/%s/xml must not error", c.name, variant.name)
					}

					if s.name == "fmt" {
						if c.expectAddr {
							t.Contains(out, "0x",
								"%s/%s/fmt must show address (structural backstop)", c.name, variant.name)
						} else {
							t.NotContains(out, "0x",
								"%s/%s/fmt must NOT show address (Format fired)", c.name, variant.name)
						}
					}
					if s.name == "slog" && c.expectAddr {
						t.Contains(out, "0x",
							"%s/%s/slog must show address (structural backstop)", c.name, variant.name)
					}
				})
			}
		}
	}
}

// TestSafety_controlStringWrapLeak proves that the non-Formatter pointer
// path truly leaks a plain sensitive.String, so Handle/Ref surviving
// it is a meaningful safety property, not a vacuous test.
func TestSafety_controlStringWrapLeak(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	secret := safetySecret
	ctl := safetyCtrlWrapT{T: &safetyCtrlSec{secret: sensitive.String(secret)}}

	// Under %s/%q, *safetyCtrlSec is a non-Formatter pointer,
	// so fmt skips safetyCtrlSec.secret's Format and prints the raw value.
	for _, verb := range []string{"%s", "%q"} {
		t.Run("verb_"+verb, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt)
			out := fmt.Sprintf(verb, ctl)
			t.Contains(out, secret,
				"control: sensitive.String MUST leak through *safetyCtrlWrapT under "+verb)
		})
	}

	// Under %v, Format IS called (no badVerb), so no leak.
	t.Run("verb_%v", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt)
		out := fmt.Sprintf("%v", ctl)
		t.NotContains(out, secret,
			"control: sensitive.String must NOT leak under %%v")
	})
}

// --- Redact-mode subprocess test ---

// testSafetyRedactMode is invoked as a subprocess entry point.
//
//nolint:revive // deep-exit: subprocess entry point.
func testSafetyRedactMode() {
	sensitive.Redact()

	checkRedacted := func(label string, v any) {
		got := fmt.Sprintf("%s", v)
		if !strings.Contains(got, "REDACTED") || strings.Contains(got, safetySecret) {
			fmt.Fprintf(os.Stderr, "FAIL: %s: got %q\n", label, got)
			os.Exit(1)
		}
	}

	// Format-fired shapes — value, exported struct field, map value,
	// map key (Handle only), slice, array, pointer-to-value.
	checkRedacted("Handle value", sensitive.Make(safetySecret))
	checkRedacted("Ref value", sensitive.New(safetySecret))

	checkRedacted("Handle exported field", safetyH{H: sensitive.Make(safetySecret)})
	checkRedacted("Ref exported field", safetyR{R: sensitive.New(safetySecret)})

	checkRedacted("Handle map value",
		map[string]sensitive.Handle[string]{"k": sensitive.Make(safetySecret)})
	checkRedacted("Ref map value",
		map[string]sensitive.Ref[string]{"k": sensitive.New(safetySecret)})

	checkRedacted("Handle map key",
		map[sensitive.Handle[string]]string{sensitive.Make(safetySecret): "v"})

	checkRedacted("Handle slice",
		[]sensitive.Handle[string]{sensitive.Make(safetySecret)})
	checkRedacted("Ref slice",
		[]sensitive.Ref[string]{sensitive.New(safetySecret)})

	checkRedacted("Handle array",
		[1]sensitive.Handle[string]{sensitive.Make(safetySecret)})
	checkRedacted("Ref array",
		[1]sensitive.Ref[string]{sensitive.New(safetySecret)})

	hPtr := sensitive.Make(safetySecret)
	checkRedacted("Handle pointer", &hPtr)
	rPtr := sensitive.New(safetySecret)
	checkRedacted("Ref pointer", &rPtr)

	os.Exit(0)
}

func TestSafety_globalModeHelper(tt *testing.T) {
	tt.Parallel()

	if os.Getenv("_SAFETY_MODE") == "" {
		tt.Skip("not running in subprocess")
	}
	testSafetyRedactMode()
}

func runSafetySubprocess(t *check.C) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSafety_globalModeHelper$")
	cmd.Env = append(os.Environ(),
		"_SAFETY_MODE=redact",
		"GO_TEST_DISABLE_SENSITIVE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Nil(err, "safety redact subprocess failed:\n%s", out)
}

func TestSafety_redactMode(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	runSafetySubprocess(t)
}
