package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWK is the Ed25519 (RFC 8037 "OKP") form. Only the public half is ever
// serialised — publishing it is the entire point, and it can verify signatures
// but never produce them.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func buildJWKS(pubs []ed25519.PublicKey) ([]byte, error) {
	set := JWKSet{Keys: make([]JWK, 0, len(pubs))}

	seen := make(map[string]struct{}, len(pubs))
	for _, pub := range pubs {
		kid := KeyID(pub)
		if _, dup := seen[kid]; dup {
			continue
		}
		seen[kid] = struct{}{}

		set.Keys = append(set.Keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Use: "sig",
			Alg: "EdDSA",
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(pub),
		})
	}

	b, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("token: marshal jwks: %w", err)
	}
	return b, nil
}

// ParseJWKS turns a published document back into verification keys, indexed by
// kid. Used by pkg/authclient in consuming services.
func ParseJWKS(raw []byte) (map[string]ed25519.PublicKey, error) {
	var set JWKSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("token: parse jwks: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue // not ours; ignore rather than fail the whole document
		}
		b, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("token: jwks key %q has an invalid x parameter", k.Kid)
		}
		keys[k.Kid] = ed25519.PublicKey(b)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("token: jwks contains no usable Ed25519 keys")
	}
	return keys, nil
}
