// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Service handles OpenID Connect specific logic.
//
// Purpose: Implementation of OIDC protocols, including discovery and token signing.
// Domain: OIDC
type Service struct {
	issuer     string
	signingKey *rsa.PrivateKey
	kid        string
}

// DiscoveryMetadata represents OIDC Discovery metadata.
//
// Purpose: Standardized configuration fields for OIDC discovery (.well-known/openid-configuration).
// Domain: OIDC
type DiscoveryMetadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
//
// Purpose: Collection of public keys for token verification.
// Domain: OIDC
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewService creates a new OIDC service.
//
// Purpose: Constructor for the OIDC protocol handler.
// Domain: OIDC
// Audited: No
// Errors: Cryptographic generation errors
func NewService(issuer string) (*Service, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	nBytes := key.PublicKey.N.Bytes()
	hash := sha256.Sum256(nBytes)
	kid := base64.RawURLEncoding.EncodeToString(hash[:16])

	return &Service{
		issuer:     issuer,
		signingKey: key,
		kid:        kid,
	}, nil
}

// GetDiscoveryMetadata returns the OIDC configuration
func (s *Service) GetDiscoveryMetadata() DiscoveryMetadata {
	return DiscoveryMetadata{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            fmt.Sprintf("%s/oauth2/authorize", s.issuer),
		TokenEndpoint:                    fmt.Sprintf("%s/oauth2/token", s.issuer),
		JWKSURI:                          fmt.Sprintf("%s/jwks.json", s.issuer),
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
	}
}

// GetJWKS returns the public keys in JWKS format
func (s *Service) GetJWKS() JWKS {
	pub := s.signingKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E))

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: s.kid,
				N:   n,
				E:   e,
			},
		},
	}
}

// GenerateIDToken generates a signed id_token JWT.
//
// Purpose: Issues a signed identity assertion for a user.
// Domain: OIDC
// Security: Creates a signed RS256 JWT with subject hashing for privacy.
// Audited: No
// Errors: JWT signing errors
func (s *Service) GenerateIDToken(userID, tenantID, clientID, nonce, accessToken string) (string, error) {
	now := time.Now()

	subSource := fmt.Sprintf("%s:%s", tenantID, userID)
	hash := sha256.Sum256([]byte(subSource))
	sub := base64.RawURLEncoding.EncodeToString(hash[:])

	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": sub,
		"aud": clientID,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	if accessToken != "" {
		atHash := sha256.Sum256([]byte(accessToken))
		leftHalf := atHash[:len(atHash)/2]
		claims["at_hash"] = base64.RawURLEncoding.EncodeToString(leftHalf)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid

	return token.SignedString(s.signingKey)
}

func bigIntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var res []byte
	for n > 0 {
		res = append([]byte{byte(n & 0xff)}, res...)
		n >>= 8
	}
	return res
}
