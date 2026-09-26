package discovery

import (
	"strings"
	"testing"
)

// A policy that cannot be read must not be silently narrowed — nor silently decided by
// whichever modifier came last, nor carry an identifier that only fails at runtime,
// where a fail-open layer would quietly skip it.
func TestParseLayersRefusesWhatItCannotRead(t *testing.T) {
	for _, bad := range []string{
		"resource fail-open fail-closed",
		"https://pdp.example fail-closed fail-open",
		"static fail-open fail-open",
		"https://",
		"http://pdp.example/?x=1 fail-open",
		"https://pdp.example#f",
		"https://user:pw@pdp.example",
		"ftp://pdp.example",
		"https://pdp.example/a/../b",
		"://pdp.example",
	} {
		if got, err := ParseLayers(bad); err == nil {
			t.Errorf("%q must not parse: %+v", bad, got)
		}
	}
	got, err := ParseLayers("https://pdp.example/tenants/a fail-open, http://estate:9098, resource")
	if err != nil || len(got) != 3 || got[0].Name != "https://pdp.example/tenants/a" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseLayers("resource fail-open fail-closed"); err == nil || !strings.Contains(err.Error(), "one failure mode") {
		t.Fatalf("the error says what is wrong: %v", err)
	}
}
