package main

import "testing"

func TestFetchAllowed(t *testing.T) {
	s := &server{base: "http://stubs", gateway: "http://stubs:9194"}
	cases := []struct {
		url  string
		want bool
	}{
		{"http://stubs:9004/.well-known/oauth-protected-resource", true},
		{"http://stubs:9002/.well-known/authzen-configuration", true},
		{"http://STUBS:9001/", true},
		{"http://stubs:9194/.well-known/openid-federation", true},
		// userinfo: the string starts with the stubs' origin, the host is elsewhere
		{"http://stubs:x@example.com/", false},
		{"http://stubs:9194@example.com/", false},
		{"http://stubs.example.com/", false},
		{"https://stubs:9004/", false},
		{"http://example.com/?u=http://stubs:9004", false},
		{"//stubs:9004/", false},
		{"stubs:9004", false},
		{"", false},
		{"http://[::1]:9099/control", false},
	}
	for _, c := range cases {
		if got := s.fetchAllowed(c.url); got != c.want {
			t.Errorf("fetchAllowed(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestFetchAllowedGatewayOnAnotherHost(t *testing.T) {
	s := &server{base: "http://localhost", gateway: "http://gw.internal:9194"}
	if !s.fetchAllowed("http://gw.internal:9194/.well-known/oauth-protected-resource") {
		t.Error("the gateway's own documents must be fetchable")
	}
	if s.fetchAllowed("http://gw.internal:9195/") {
		t.Error("another port on the gateway's host is not the gateway")
	}
	if s.fetchAllowed("http://localhost:9194@gw.internal:1/") {
		t.Error("userinfo must not smuggle a different host")
	}
}
