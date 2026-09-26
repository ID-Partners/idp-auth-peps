package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// P7: in off mode (the default) ResolvePDP skipped PDP_ALLOWLIST and the https check for
// route layers — which arrive over the HTTP check API from its caller — so any URL a
// caller named became a PDP the PEP posted decisions to.
func TestOffModeChecksRouteLayers(t *testing.T) {
	strict, err := New(Options{Mode: ModeOff, StaticPDP: "https://static.example", Logf: func(string, ...any) {},
		PDPAllowed: func(u string) bool { return strings.HasPrefix(u, "https://pdp.example/") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, pdp := range []string{"http://10.0.0.1:8080", "https://elsewhere.example"} {
		if _, err := strict.ResolvePDP(ctx(), pdp); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: off mode must apply the allowlist: %v", pdp, err)
		}
	}
	if ep, err := strict.ResolvePDP(ctx(), "https://pdp.example/t/a"); err != nil || ep.Evaluation != "https://pdp.example/t/a/access/v1/evaluation" {
		t.Fatalf("an allowlisted layer: %+v %v", ep, err)
	}
	// Without an allowlist, the scheme still holds: http only for the operator's own
	// origin, or when insecure metadata is allowed.
	static := Static("https://static.example", "k")
	if _, err := static.ResolvePDP(ctx(), "http://internal.example"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("http must be refused: %v", err)
	}
	// A refused layer is never skipped, whatever its mode.
	open := true
	if _, err := ResolveLayers(ctx(), static, "", []LayerSpec{{Name: "http://internal.example", FailOpen: &open}}, true); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a refusal must not fail open: %v", err)
	}
}

// P10: a document could name a configured fail-open layer as its own PDP, and dedupe
// kept the configured mode — so the resource's own decision became skippable. The slot
// that carries the resource's PDP keeps the stricter of the two modes.
func TestTheResourcesOwnPDPKeepsTheStricterMode(t *testing.T) {
	estate := newPDP(t, fullConfig)
	static := newPDP(t, nil)
	res := newResource(t, func(self string) any {
		return map[string]any{"resource": self, ParamPolicyDecisionPoints: []string{estate.URL}}
	})
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL})
	open := true
	for _, layers := range [][]LayerSpec{
		{{Name: estate.URL, FailOpen: &open}, {Name: LayerResource}},
		{{Name: LayerResource}, {Name: estate.URL, FailOpen: &open}},
	} {
		r, err := ResolveLayers(ctx(), c, res.URL, layers, false)
		if err != nil || len(r.PDPs) != 1 || r.PDPs[0].FailOpen || r.PDPs[0].Resource == nil {
			t.Fatalf("%v: the resource's own PDP must not inherit a configured fail-open: %+v %v", LayerNames(layers), r.PDPs, err)
		}
	}
	// The resource entry's own fail-open is still its own to set.
	r, err := ResolveLayers(ctx(), c, res.URL, []LayerSpec{{Name: estate.URL, FailOpen: &open}, {Name: LayerResource, FailOpen: &open}}, false)
	if err != nil || !r.PDPs[0].FailOpen {
		t.Fatalf("%+v %v", r.PDPs, err)
	}
}

// A 404 means the resource publishes nothing, and the static PDP answers for it, by
// design. An outage or an unreadable document is the resource layer being unavailable:
// it fails by its mode — closed by default, skipped and named when fail-open. Both used
// to collapse silently into the static layer.
func TestAnOutageIsNotAResourceThatPublishesNothing(t *testing.T) {
	static := newPDP(t, nil)
	down := newResource(t, fullConfig)
	down.status = 503
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL})
	if _, err := ResolveLayers(ctx(), c, down.URL, specs(LayerStatic, LayerResource), false); err == nil || errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an outage fails the resource layer, closed by default: %v", err)
	}
	open := true
	r, err := ResolveLayers(ctx(), c, down.URL, []LayerSpec{{Name: LayerStatic}, {Name: LayerResource, FailOpen: &open}}, false)
	if err != nil || !reflect.DeepEqual(idsOf(r.PDPs), []string{static.URL}) || !reflect.DeepEqual(r.Skipped, []string{LayerResource}) {
		t.Fatalf("fail-open skips it and says so: %+v %v", r, err)
	}
	if len(r.SkippedReasons) != 1 || !strings.Contains(r.SkippedReasons[0], "503") {
		t.Fatalf("the reason is kept for the log: %v", r.SkippedReasons)
	}
	// An unreadable document is no different.
	bad := newResource(t, func(string) any { return "<html>" })
	if _, err := ResolveLayers(ctx(), c, bad.URL, specs(LayerResource), false); err == nil {
		t.Fatal("an unreadable document must not become the static PDP's")
	}
	// A 404 is static, and [static, resource] is then one call, not a skip.
	none := newResource(t, nil)
	r, err = ResolveLayers(ctx(), c, none.URL, specs(LayerStatic, LayerResource), false)
	if err != nil || !reflect.DeepEqual(idsOf(r.PDPs), []string{static.URL}) || len(r.Skipped) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

// A PDP whose metadata endpoint blips kept its default endpoint paths as a success for a
// whole TTL, replacing what it had advertised. The last good entry is served instead;
// with nothing cached the PDP is unavailable, not guessed at, and that is remembered
// briefly.
func TestAPDPMetadataBlipServesTheLastGoodEntry(t *testing.T) {
	now := time.Now()
	pdp := newPDP(t, fullConfig)
	c := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: pdp.URL, TTL: time.Minute, Now: func() time.Time { return now }})
	if ep, err := c.Resolve(ctx(), ""); err != nil || ep.Evaluation != pdp.URL+"/custom/eval" {
		t.Fatalf("%+v %v", ep, err)
	}
	pdp.status = 500
	now = now.Add(61 * time.Second)
	if ep, err := c.Resolve(ctx(), ""); err != nil || ep.Evaluation != pdp.URL+"/custom/eval" {
		t.Fatalf("the advertised endpoint must survive a blip: %+v %v", ep, err)
	}
	flaky := newPDP(t, fullConfig)
	flaky.status = 500
	c2 := mustNew(t, Options{Mode: ModeAuthZEN, StaticPDP: flaky.URL})
	if ep, err := c2.Resolve(ctx(), ""); err == nil {
		t.Fatalf("with nothing cached a blip is unavailability, not the default paths: %+v", ep)
	}
	hits := atomic.LoadInt32(&flaky.hits)
	c2.Resolve(ctx(), "")
	if atomic.LoadInt32(&flaky.hits) != hits {
		t.Fatal("a failed metadata fetch must be remembered briefly, not repeated per request")
	}
}

// A document may name only so many PDPs: each is a metadata fetch and, as a layer, a
// decision call per request.
func TestListedPDPsAreBounded(t *testing.T) {
	static := newPDP(t, nil)
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("https://pdp%d.example", i)
		}
		return out
	}
	c := mustNew(t, Options{Mode: ModeResource, StaticPDP: static.URL})
	for name, doc := range map[string]func(self string) any{
		"candidates": func(self string) any {
			return map[string]any{"resource": self, ParamPolicyDecisionPoints: many(maxListedPDPs + 1)}
		},
		"layers": func(self string) any {
			return map[string]any{"resource": self, ParamPolicyDecisionPoints: many(1), ParamPolicyLayers: many(maxListedPDPs + 1)}
		},
	} {
		r := newResource(t, doc)
		if _, err := c.Resolve(ctx(), r.URL); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Errorf("%s: a list past the cap makes the document unusable: %v", name, err)
		}
	}
}
