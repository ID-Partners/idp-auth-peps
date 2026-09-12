package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ID-Partners/idp-auth-peps/core/authzen/discovery"
)

// A permitting layer's obligation must survive a later layer's plain permit.
//
// This is the test that was missing. Every layer was individually correct; the defect
// lived in how two correct permits combined, so a generic PDP's "permit, but step up"
// was erased by the resource PDP's "permit" and the request went through with no
// challenge issued at all.
func TestLayerFoldKeepsObligationsAcrossPermits(t *testing.T) {
	pdp := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}
	const stepUpFirst = `{"decision":true,"context":{"reason":"step up for this amount","step_up_required":true,"step_up_scope":"banking:payments:transfer"}}`
	const identityFirst = `{"decision":true,"context":{"reason":"prove who you are","identity_proofing_required":true,"identity_proofing_doctype":"org.iso.18013.5.1.mDL"}}`
	const plainPermit = `{"decision":true,"context":{"reason":"resource is fine"}}`

	t.Run("step-up survives", func(t *testing.T) {
		generic, resource := pdp(stepUpFirst), pdp(plainPermit)
		defer generic.Close()
		defer resource.Close()
		out := fold(t, generic.URL, resource.URL)
		if !out.Decision {
			t.Fatalf("both layers permitted, want a permit: %+v", out)
		}
		if !out.StepUp {
			t.Fatal("the generic layer required a step-up and the resource layer's permit erased it")
		}
		if out.StepUpScope != "banking:payments:transfer" {
			t.Fatalf("the requiring layer owns the scope, got %q", out.StepUpScope)
		}
		if out.Reason != "step up for this amount" {
			t.Fatalf("the obligation's reason should explain the challenge, got %q", out.Reason)
		}
	})

	t.Run("identity proofing survives", func(t *testing.T) {
		generic, resource := pdp(identityFirst), pdp(plainPermit)
		defer generic.Close()
		defer resource.Close()
		out := fold(t, generic.URL, resource.URL)
		if !out.IdentityReq {
			t.Fatal("the generic layer required identity proofing and the resource layer's permit erased it")
		}
		if out.IdentityDoctype != "org.iso.18013.5.1.mDL" {
			t.Fatalf("the requiring layer owns the doctype, got %q", out.IdentityDoctype)
		}
	})

	t.Run("obligation from either position survives", func(t *testing.T) {
		// The same must hold when it is the LAST layer that requires it.
		first, second := pdp(plainPermit), pdp(stepUpFirst)
		defer first.Close()
		defer second.Close()
		if out := fold(t, first.URL, second.URL); !out.StepUp {
			t.Fatal("an obligation from the last layer was lost")
		}
	})

	t.Run("a deny still short-circuits with its own advice", func(t *testing.T) {
		deny := pdp(`{"decision":false,"context":{"reason":"no","step_up_required":true,"step_up_scope":"s"}}`)
		unreached := pdp(plainPermit)
		defer deny.Close()
		defer unreached.Close()
		out := fold(t, deny.URL, unreached.URL)
		if out.Decision {
			t.Fatal("a deny in the first layer must be the answer")
		}
		if !out.StepUp || out.Reason != "no" {
			t.Fatalf("the denying layer's advice must survive: %+v", out)
		}
	})

	t.Run("every layer still had to permit", func(t *testing.T) {
		permit, deny := pdp(plainPermit), pdp(`{"decision":false,"context":{"reason":"second says no"}}`)
		defer permit.Close()
		defer deny.Close()
		if out := fold(t, permit.URL, deny.URL); out.Decision {
			t.Fatal("a deny in any layer denies the request")
		}
	})

	t.Run("fail-open with nothing reachable is still a marked permit", func(t *testing.T) {
		s := &server{httpc: http.DefaultClient}
		eps := []discovery.PDPEndpoints{{Identifier: "gone", Evaluation: "http://127.0.0.1:1/x", FailOpen: true}}
		out, err := s.evaluateLayers(context.Background(), eps, map[string]any{}, nil)
		if err != nil {
			t.Fatalf("fail-open must not error: %v", err)
		}
		if !out.Decision || !strings.Contains(out.Reason, "fail-open") {
			t.Fatalf("want a permit marked fail-open, got %+v", out)
		}
	})
}

func fold(t *testing.T, urls ...string) pepOutcome {
	t.Helper()
	s := &server{httpc: http.DefaultClient}
	eps := make([]discovery.PDPEndpoints, 0, len(urls))
	for i, u := range urls {
		eps = append(eps, discovery.PDPEndpoints{Identifier: string(rune('a' + i)), Evaluation: u})
	}
	out, err := s.evaluateLayers(context.Background(), eps, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return out
}
