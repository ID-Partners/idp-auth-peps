package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// mintProof builds a real compact JWS DPoP proof signed by key.
func mintProof(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	jwk := publicJWK(key)
	hdr := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := enc(hdr) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func publicJWK(key *ecdsa.PrivateKey) map[string]any {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const testToken = "an.access.token"

func boundClaims(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{"cnf": map[string]any{"jkt": jwkThumbprint(publicJWK(key))}}
}

func freshProofClaims(jti string) map[string]any {
	return map[string]any{
		"htm": "POST",
		"htu": "https://api.example.com/payments",
		"ath": accessTokenHash(testToken),
		"iat": float64(time.Now().Unix()),
		"jti": jti,
	}
}

func TestDpopAcceptsAValidProof(t *testing.T) {
	key := newKey(t)
	proof := mintProof(t, key, freshProofClaims("jti-valid-1"))
	got := checkDpop("test", "dpop", "POST", "/payments", testToken,
		map[string]string{"dpop": proof}, boundClaims(key))
	if got != nil {
		t.Fatalf("expected the proof to be accepted, got a denial")
	}
}

// The regression that matters: before signature verification, an attacker who had seen
// one proof could copy its public JWK — the jkt matches — and sign with their own key.
func TestDpopRejectsAForgedProofWithACopiedJWK(t *testing.T) {
	victim := newKey(t)
	attacker := newKey(t)

	// The attacker signs with their own key but advertises the victim's public JWK,
	// so the thumbprint still equals the token's cnf.jkt.
	forged := mintProof(t, attacker, freshProofClaims("jti-forged-1"))
	hdr := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": publicJWK(victim)}
	raw, _ := json.Marshal(hdr)
	parts := splitJWS(t, forged)
	swapped := base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1] + "." + parts[2]

	got := checkDpop("test", "dpop", "POST", "/payments", testToken,
		map[string]string{"dpop": swapped}, boundClaims(victim))
	if got == nil {
		t.Fatal("a proof signed by the wrong key was accepted")
	}
}

// A proof minted for one token must not replay against another.
func TestDpopRejectsAthForADifferentToken(t *testing.T) {
	key := newKey(t)
	claims := freshProofClaims("jti-ath-1")
	claims["ath"] = accessTokenHash("a.different.token")
	proof := mintProof(t, key, claims)

	got := checkDpop("test", "dpop", "POST", "/payments", testToken,
		map[string]string{"dpop": proof}, boundClaims(key))
	if got == nil {
		t.Fatal("a proof bound to a different access token was accepted")
	}
}

func TestDpopRejectsReplayOfTheSameJti(t *testing.T) {
	key := newKey(t)
	proof := mintProof(t, key, freshProofClaims("jti-replay-1"))
	headers := map[string]string{"dpop": proof}

	if got := checkDpop("test", "dpop", "POST", "/payments", testToken, headers, boundClaims(key)); got != nil {
		t.Fatal("first use should be accepted")
	}
	if got := checkDpop("test", "dpop", "POST", "/payments", testToken, headers, boundClaims(key)); got == nil {
		t.Fatal("the same proof was accepted twice")
	}
}

func TestDpopRejectsAStaleProof(t *testing.T) {
	key := newKey(t)
	claims := freshProofClaims("jti-stale-1")
	claims["iat"] = float64(time.Now().Add(-2 * dpopMaxAge).Unix())
	proof := mintProof(t, key, claims)

	got := checkDpop("test", "dpop", "POST", "/payments", testToken,
		map[string]string{"dpop": proof}, boundClaims(key))
	if got == nil {
		t.Fatal("a proof well outside the acceptance window was accepted")
	}
}

func TestDpopRejectsUnboundAndMalformedProofs(t *testing.T) {
	key := newKey(t)
	other := newKey(t)

	cases := []struct {
		name    string
		scheme  string
		method  string
		token   string
		proof   string
		claims  map[string]any
		wantErr bool
	}{
		{name: "bearer scheme", scheme: "bearer", method: "POST", token: testToken,
			proof: mintProof(t, key, freshProofClaims("j1")), claims: boundClaims(key), wantErr: true},
		{name: "no proof header", scheme: "dpop", method: "POST", token: testToken,
			proof: "", claims: boundClaims(key), wantErr: true},
		{name: "not a JWT", scheme: "dpop", method: "POST", token: testToken,
			proof: "garbage", claims: boundClaims(key), wantErr: true},
		{name: "jkt bound to another key", scheme: "dpop", method: "POST", token: testToken,
			proof: mintProof(t, key, freshProofClaims("j2")), claims: boundClaims(other), wantErr: true},
		{name: "htm mismatch", scheme: "dpop", method: "GET", token: testToken,
			proof: mintProof(t, key, freshProofClaims("j3")), claims: boundClaims(key), wantErr: true},
		{name: "token absent", scheme: "dpop", method: "POST", token: "",
			proof: mintProof(t, key, freshProofClaims("j4")), claims: boundClaims(key), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkDpop("test", tc.scheme, tc.method, "/payments", tc.token,
				map[string]string{"dpop": tc.proof}, tc.claims)
			if tc.wantErr && got == nil {
				t.Fatal("expected a denial, got none")
			}
		})
	}
}

func TestDpopRejectsAProofLeakingPrivateKeyMaterial(t *testing.T) {
	key := newKey(t)
	jwk := publicJWK(key)
	jwk["d"] = "definitely-private"
	hdr := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
	raw, _ := json.Marshal(hdr)
	proof := mintProof(t, key, freshProofClaims("jti-priv-1"))
	parts := splitJWS(t, proof)
	tainted := base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1] + "." + parts[2]

	if got := checkDpop("test", "dpop", "POST", "/payments", testToken,
		map[string]string{"dpop": tainted}, boundClaims(key)); got == nil {
		t.Fatal("a proof carrying private key material was accepted")
	}
}

func TestReplayCacheExpiresEntries(t *testing.T) {
	c := newReplayCache(50 * time.Millisecond)
	now := time.Now()
	if !c.observe("a", now) {
		t.Fatal("first observation should be fresh")
	}
	if c.observe("a", now) {
		t.Fatal("immediate repeat should be a replay")
	}
	if !c.observe("a", now.Add(100*time.Millisecond)) {
		t.Fatal("the entry should have aged out of the window")
	}
	if c.observe("", now) {
		t.Fatal("an empty jti must never be accepted")
	}
}

func splitJWS(t *testing.T, jws string) [3]string {
	t.Helper()
	var out [3]string
	n, start := 0, 0
	for i := 0; i < len(jws); i++ {
		if jws[i] == '.' {
			out[n] = jws[start:i]
			n++
			start = i + 1
			if n == 2 {
				break
			}
		}
	}
	out[2] = jws[start:]
	return out
}
