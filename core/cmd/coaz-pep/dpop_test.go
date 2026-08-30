package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// ---------------------------------------------------------------------------
// Key parsing and signature verification across the algorithms a real client emits.

func rsaJWK(t *testing.T, key *rsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
	}
}

func TestVerifyProofSignatureRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := rsaJWK(t, key)

	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	claims := map[string]any{"htm": "POST", "jti": "r1", "iat": float64(time.Now().Unix())}

	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			hdr := map[string]any{"typ": "dpop+jwt", "alg": alg, "jwk": jwk}
			signingInput := enc(hdr) + "." + enc(claims)
			hash, err := hashFor(alg)
			if err != nil {
				t.Fatal(err)
			}
			digest := hashBytes(hash, []byte(signingInput))

			var sig []byte
			if strings.HasPrefix(alg, "PS") {
				sig, err = rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			} else {
				sig, err = rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
			}
			if err != nil {
				t.Fatal(err)
			}
			proof := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

			if err := verifyProofSignature(proof, jwk, alg); err != nil {
				t.Fatalf("a genuine %s proof should verify: %v", alg, err)
			}
			// Tamper with the payload: the signature must stop matching.
			tampered := enc(hdr) + "." + enc(map[string]any{"htm": "GET"}) + "." +
				base64.RawURLEncoding.EncodeToString(sig)
			if err := verifyProofSignature(tampered, jwk, alg); err == nil {
				t.Fatalf("a tampered %s proof was accepted", alg)
			}
		})
	}
}

func TestHashForCoversEverySupportedSize(t *testing.T) {
	for _, alg := range []string{"ES256", "RS384", "PS512"} {
		if _, err := hashFor(alg); err != nil {
			t.Errorf("%s should be supported: %v", alg, err)
		}
	}
	for _, alg := range []string{"", "HS256", "EdDSA", "ES128"} {
		if _, err := hashFor(alg); err == nil {
			t.Errorf("%q should not be accepted", alg)
		}
	}
}

func TestKeyParsingRejectsMismatchedOrBrokenJWKs(t *testing.T) {
	ecKey := newKey(t)
	ecJWK := publicJWK(ecKey)

	// alg family must match the key type, or a proof could be verified with the wrong
	// algorithm entirely.
	if _, err := rsaFromJWK(ecJWK); err == nil {
		t.Error("an EC JWK must not parse as RSA")
	}
	if _, err := ecdsaFromJWK(map[string]any{"kty": "RSA"}); err == nil {
		t.Error("an RSA JWK must not parse as EC")
	}

	for name, jwk := range map[string]map[string]any{
		"unknown curve":  {"kty": "EC", "crv": "P-192", "x": "AA", "y": "AA"},
		"x not base64":   {"kty": "EC", "crv": "P-256", "x": "!!!", "y": "AA"},
		"not on curve":   {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ"},
		"empty modulus":  {"kty": "RSA", "n": "", "e": "AQAB"},
		"empty exponent": {"kty": "RSA", "n": "AQ", "e": ""},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if jwk["kty"] == "EC" {
				_, err = ecdsaFromJWK(jwk)
			} else {
				_, err = rsaFromJWK(jwk)
			}
			if err == nil {
				t.Fatalf("%s should be refused", name)
			}
		})
	}
}

func TestVerifyProofSignatureRejectsMalformed(t *testing.T) {
	key := newKey(t)
	jwk := publicJWK(key)
	for name, proof := range map[string]string{
		"not a JWS":        "a.b",
		"signature junk":   "aGVhZGVy.Y2xhaW1z.!!!",
		"wrong sig length": "aGVhZGVy.Y2xhaW1z." + base64.RawURLEncoding.EncodeToString([]byte("short")),
	} {
		t.Run(name, func(t *testing.T) {
			if err := verifyProofSignature(proof, jwk, "ES256"); err == nil {
				t.Fatal("expected a verification failure")
			}
		})
	}
	if err := verifyProofSignature("a.b.c", jwk, "HS256"); err == nil {
		t.Fatal("an unsupported alg must not verify")
	}
}

func TestReplayCacheRefusesWhenFullOfLiveEntries(t *testing.T) {
	c := newReplayCache(time.Hour)
	c.maxSize = 3
	now := time.Now()
	for i, jti := range []string{"a", "b", "c"} {
		if !c.observe(jti, now) {
			t.Fatalf("entry %d should be accepted", i)
		}
	}
	// Full, nothing expired: refuse rather than grow without bound. Failing closed
	// under a jti flood is the safe direction.
	if c.observe("d", now) {
		t.Fatal("a full cache with no expired entries must refuse, not grow")
	}
	// Once entries age out, it accepts again.
	if !c.observe("d", now.Add(2*time.Hour)) {
		t.Fatal("expired entries should be reclaimed")
	}
}

// ---------------------------------------------------------------------------
// The delegated verification endpoint the Kong plugin calls.

func postVerify(t *testing.T, s *server, body string) (int, dpopVerifyResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleDpopVerify(rec, httptest.NewRequest(http.MethodPost, "/v1/dpop/verify", strings.NewReader(body)))
	var out dpopVerifyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestDpopVerifyEndpoint(t *testing.T) {
	s := &server{}
	key := newKey(t)
	thumb := jwkThumbprint(publicJWK(key))
	token := mintUnsigned(map[string]any{"sub": "alice", "cnf": map[string]any{"jkt": thumb}})

	makeBody := func(proof string) string {
		raw, _ := json.Marshal(map[string]any{
			"method": "POST", "path": "/payments", "pep_label": "kong",
			"headers": map[string]string{"Authorization": "DPoP " + token, "DPoP": proof},
		})
		return string(raw)
	}

	t.Run("valid proof", func(t *testing.T) {
		proof := mintProof(t, key, map[string]any{
			"htm": "POST", "ath": accessTokenHash(token),
			"iat": float64(time.Now().Unix()), "jti": "verify-ok-1",
		})
		code, out := postVerify(t, s, makeBody(proof))
		if code != http.StatusOK || !out.Valid {
			t.Fatalf("a genuine proof should verify: code=%d out=%+v", code, out)
		}
	})

	t.Run("forged proof is refused with a reason", func(t *testing.T) {
		// Signed by the attacker, advertising the victim's JWK — the exact forgery a
		// thumbprint-only check would accept, and the reason this endpoint exists.
		attacker := newKey(t)
		forged := mintProof(t, attacker, map[string]any{
			"htm": "POST", "ath": accessTokenHash(token),
			"iat": float64(time.Now().Unix()), "jti": "verify-forged-1",
		})
		hdr, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": publicJWK(key)})
		parts := splitJWS(t, forged)
		swapped := base64.RawURLEncoding.EncodeToString(hdr) + "." + parts[1] + "." + parts[2]

		code, out := postVerify(t, s, makeBody(swapped))
		if code != http.StatusOK {
			t.Fatalf("the endpoint answers 200 with a verdict, got %d", code)
		}
		if out.Valid {
			t.Fatal("a proof signed by the wrong key must not verify")
		}
		if out.Reason == "" || out.Status != 401 {
			t.Fatalf("a refusal should carry a reason and a status, got %+v", out)
		}
	})

	t.Run("ath bound to another token", func(t *testing.T) {
		proof := mintProof(t, key, map[string]any{
			"htm": "POST", "ath": accessTokenHash("a.different.token"),
			"iat": float64(time.Now().Unix()), "jti": "verify-ath-1",
		})
		if _, out := postVerify(t, s, makeBody(proof)); out.Valid {
			t.Fatal("a proof bound to a different token must not verify")
		}
	})

	t.Run("replay", func(t *testing.T) {
		proof := mintProof(t, key, map[string]any{
			"htm": "POST", "ath": accessTokenHash(token),
			"iat": float64(time.Now().Unix()), "jti": "verify-replay-1",
		})
		if _, out := postVerify(t, s, makeBody(proof)); !out.Valid {
			t.Fatal("first use should verify")
		}
		if _, out := postVerify(t, s, makeBody(proof)); out.Valid {
			t.Fatal("the same proof must not verify twice")
		}
	})

	t.Run("bearer scheme and missing proof", func(t *testing.T) {
		raw, _ := json.Marshal(map[string]any{
			"method": "POST", "path": "/payments",
			"headers": map[string]string{"Authorization": "Bearer " + token},
		})
		if _, out := postVerify(t, s, string(raw)); out.Valid {
			t.Fatal("a bearer token carries no sender-constraint to verify")
		}
	})

	t.Run("malformed request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleDpopVerify(rec, httptest.NewRequest(http.MethodPost, "/v1/dpop/verify", strings.NewReader("{{{")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a malformed body should be a 400, got %d", rec.Code)
		}
	})

	t.Run("header case does not matter", func(t *testing.T) {
		// Kong sends whatever case the client used; a case-sensitive lookup would make
		// every proof look absent.
		proof := mintProof(t, key, map[string]any{
			"htm": "POST", "ath": accessTokenHash(token),
			"iat": float64(time.Now().Unix()), "jti": "verify-case-1",
		})
		raw, _ := json.Marshal(map[string]any{
			"method": "POST", "path": "/payments",
			"headers": map[string]string{"AUTHORIZATION": "DPoP " + token, "DPOP": proof},
		})
		if _, out := postVerify(t, s, string(raw)); !out.Valid {
			t.Fatalf("upper-cased headers should still be found: %+v", out)
		}
	})
}

func TestDpopProofHeaderGuards(t *testing.T) {
	key := newKey(t)
	claims := boundClaims(key)
	base := freshProofClaims("guard-1")

	// typ must be dpop+jwt.
	badTyp := signWithHeader(t, key, map[string]any{"typ": "jwt", "alg": "ES256", "jwk": publicJWK(key)}, base)
	if checkDpop("t", "dpop", "POST", "/p", testToken, map[string]string{"dpop": badTyp}, claims) == nil {
		t.Error("a proof without typ=dpop+jwt must be rejected")
	}
	// alg none.
	noneAlg := signWithHeader(t, key, map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": publicJWK(key)}, base)
	if checkDpop("t", "dpop", "POST", "/p", testToken, map[string]string{"dpop": noneAlg}, claims) == nil {
		t.Error("alg=none must be rejected")
	}
	// missing ath.
	noAth := freshProofClaims("guard-ath")
	delete(noAth, "ath")
	if checkDpop("t", "dpop", "POST", "/p", testToken, map[string]string{"dpop": mintProof(t, key, noAth)}, claims) == nil {
		t.Error("a proof with no ath must be rejected")
	}
	// missing iat.
	noIat := freshProofClaims("guard-iat")
	delete(noIat, "iat")
	if checkDpop("t", "dpop", "POST", "/p", testToken, map[string]string{"dpop": mintProof(t, key, noIat)}, claims) == nil {
		t.Error("a proof with no iat must be rejected")
	}
	// htu mismatch is logged, not fatal — a proof otherwise valid still passes.
	withHtu := freshProofClaims("guard-htu")
	withHtu["htu"] = "https://elsewhere.example/totally-different"
	if r := checkDpop("t", "dpop", "POST", "/payments", testToken, map[string]string{"dpop": mintProof(t, key, withHtu)}, claims); r != nil {
		t.Error("an htu mismatch should be logged, not fatal")
	}
}

// signWithHeader mints a proof with an arbitrary header, for the header-guard tests.
func signWithHeader(t *testing.T, key *ecdsa.PrivateKey, hdr map[string]any, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := enc(hdr) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestECDSAFromJWKCurves(t *testing.T) {
	// P-384 and P-521 key parsing, so both non-P-256 arms run.
	for _, tc := range []struct {
		crv   string
		curve elliptic.Curve
	}{{"P-384", elliptic.P384()}, {"P-521", elliptic.P521()}} {
		k, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n := (tc.curve.Params().BitSize + 7) / 8
		x, y := make([]byte, n), make([]byte, n)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		jwk := map[string]any{"kty": "EC", "crv": tc.crv,
			"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
		if _, err := ecdsaFromJWK(jwk); err != nil {
			t.Errorf("%s should parse: %v", tc.crv, err)
		}
	}
}

func TestRSAExponentOutOfRange(t *testing.T) {
	// An exponent larger than 2^31 is refused rather than silently truncated.
	jwk := map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		"e": base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff, 0xff, 0xff, 0xff})}
	if _, err := rsaFromJWK(jwk); err == nil {
		t.Fatal("an oversized RSA exponent must be refused")
	}
}

func TestHashForUnsupported(t *testing.T) {
	if _, err := hashFor("ES999"); err == nil {
		t.Fatal("an unknown alg size must be unsupported")
	}
}

func TestVerifyProofSignatureUnsupportedAlg(t *testing.T) {
	// verifyProofSignature reached directly with an alg outside ES/RS/PS: the final
	// unsupported-alg return. checkDpop guards typ/alg upstream, so this is the
	// belt-and-braces arm.
	key := newKey(t)
	proof := mintProof(t, key, freshProofClaims("j"))
	if err := verifyProofSignature(proof, publicJWK(key), "EdDSA"); err == nil {
		t.Fatal("EdDSA is not a supported proof alg here")
	}
}

func TestDpopProofWithNoJWK(t *testing.T) {
	// A proof header with no jwk member: the "carries no jwk" arm.
	key := newKey(t)
	hdr := map[string]any{"typ": "dpop+jwt", "alg": "ES256"} // no jwk
	proof := signWithHeader(t, key, hdr, freshProofClaims("nojwk"))
	if checkDpop("t", "dpop", "POST", "/p", testToken, map[string]string{"dpop": proof}, boundClaims(key)) == nil {
		t.Fatal("a proof with no jwk in its header must be rejected")
	}
}
