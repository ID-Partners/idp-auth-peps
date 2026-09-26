package metafetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A document with a media type of its own is only that document when it is served as
// one. Parameters and case are tolerated; anything else is ErrContentType.
func TestGetTyped(t *testing.T) {
	const want = "application/entity-statement+jwt"
	var served, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		if served != "" {
			w.Header().Set("Content-Type", served)
		}
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte("a.b.c"))
	}))
	defer srv.Close()
	c := New(srv.Client(), Policy{AllowInsecure: true}, "", 0)
	for _, ok := range []string{want, "Application/Entity-Statement+JWT; charset=utf-8"} {
		served = ok
		if body, err := c.GetTyped(context.Background(), srv.URL+"/es", want); err != nil || string(body) != "a.b.c" || gotAccept != want {
			t.Fatalf("%q: %q %v (accept %q)", ok, body, err, gotAccept)
		}
	}
	for _, bad := range []string{"application/json", "text/plain; charset=utf-8", "application/jwt", "", ";;"} {
		served = bad
		if _, err := c.GetTyped(context.Background(), srv.URL+"/es", want); !errors.Is(err, ErrContentType) {
			t.Errorf("%q: want ErrContentType, got %v", bad, err)
		}
	}
	// A 404 is still a 404, whatever it is served as.
	served = "text/plain"
	if _, err := c.GetTyped(context.Background(), srv.URL+"/gone", want); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}
