package coaz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

// A permitting layer's obligation must survive a later layer's plain permit.
//
// The COAZ engine consults obligations only on a deny today, so overwriting them changed
// no outcome here — but the fold is the same shape that was live in the gateway PEPs, and
// it becomes live the moment these checks move out of the deny branch. Pinned so it
// cannot drift back.
func TestLayerFoldKeepsObligationsAcrossPermits(t *testing.T) {
	pdp := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}
	generic := pdp(`{"decision":true,"context":{"reason":"step up","step_up_required":true,"step_up_scope":"banking:payments:transfer"}}`)
	defer generic.Close()
	resource := pdp(`{"decision":true,"context":{"reason":"fine"}}`)
	defer resource.Close()

	e := &Engine{pdpc: http.DefaultClient}
	eps := []discovery.PDPEndpoints{
		{Identifier: "generic", Evaluation: generic.URL},
		{Identifier: "resource", Evaluation: resource.URL},
	}
	out, err := e.evaluateLayers(context.Background(), eps, &BuiltRequest{Body: []byte(`{}`)}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Decision {
		t.Fatalf("both layers permitted, want a permit: %+v", out)
	}
	if !out.StepUp || out.StepUpScope != "banking:payments:transfer" {
		t.Fatalf("the generic layer's step-up was erased by the resource layer's permit: %+v", out)
	}
	if out.Reason != "step up" {
		t.Fatalf("the obligation's reason should explain the challenge, got %q", out.Reason)
	}
}
