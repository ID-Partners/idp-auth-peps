package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
)

// Sign mints a compact JWS over claims with the given protected header. The alg is read
// from header["alg"]; the key must match its family. Meant for fixtures and for the
// in-process federations the tests stand up — the PEP itself signs nothing in production.
func Sign(header, claims map[string]any, key crypto.Signer) (string, error) {
	alg, _ := header["alg"].(string)
	hash, err := HashFor(alg)
	if err != nil {
		return "", err
	}
	hdr, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := B64URLEncode(hdr) + "." + B64URLEncode(body)
	digest := HashBytes(hash, []byte(input))

	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if alg[:2] != "ES" {
			return "", fmt.Errorf("alg %s cannot be signed with an EC key", alg)
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return "", err
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*n)
		r.FillBytes(sig[:n])
		s.FillBytes(sig[n:])
	case *rsa.PrivateKey:
		switch alg[:2] {
		case "PS":
			sig, err = rsa.SignPSS(rand.Reader, k, hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		case "RS":
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
		default:
			return "", fmt.Errorf("alg %s cannot be signed with an RSA key", alg)
		}
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported signing key %T", key)
	}
	return input + "." + B64URLEncode(sig), nil
}

// PublicJWK renders the public half of an EC or RSA key as a JWK. The kid is the
// RFC 7638 thumbprint, which is what OpenID Federation recommends.
func PublicJWK(key crypto.Signer) (map[string]any, error) {
	var jwk map[string]any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		x := make([]byte, n)
		y := make([]byte, n)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		jwk = map[string]any{
			"kty": "EC", "crv": k.Curve.Params().Name,
			"x": B64URLEncode(x), "y": B64URLEncode(y),
		}
	case *rsa.PrivateKey:
		jwk = map[string]any{
			"kty": "RSA",
			"n":   B64URLEncode(k.N.Bytes()),
			"e":   B64URLEncode([]byte{1, 0, 1}),
		}
	default:
		return nil, fmt.Errorf("unsupported key %T", key)
	}
	jwk["kid"] = Thumbprint(jwk)
	return jwk, nil
}
