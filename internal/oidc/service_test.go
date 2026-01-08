// Copyright 2026 The OpenTrusty Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDiscoveryMetadata(t *testing.T) {
	issuer := "https://auth.example.com"
	svc, _ := NewService(issuer)
	meta := svc.GetDiscoveryMetadata()

	if meta.Issuer != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, meta.Issuer)
	}

	expectedAuth := issuer + "/oauth2/authorize"
	if meta.AuthorizationEndpoint != expectedAuth {
		t.Errorf("expected auth endpoint %s, got %s", expectedAuth, meta.AuthorizationEndpoint)
	}
}

func TestJWKS(t *testing.T) {
	svc, _ := NewService("https://auth.example.com")
	jwks := svc.GetJWKS()

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if key.Kid != svc.kid {
		t.Errorf("expected kid %s, got %s", svc.kid, key.Kid)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected RS256, got %s", key.Alg)
	}
}

func TestGenerateIDToken(t *testing.T) {
	issuer := "https://auth.example.com"
	svc, _ := NewService(issuer)

	userID := "u1"
	tenantID := "t1"
	clientID := "c1"
	nonce := "random-nonce"
	accessToken := "at-123"

	tokenStr, err := svc.GenerateIDToken(userID, tenantID, clientID, nonce, accessToken)
	if err != nil {
		t.Fatalf("failed to generate ID token: %v", err)
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &svc.signingKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)

	// Verify sub (hashed)
	subSource := fmt.Sprintf("%s:%s", tenantID, userID)
	hash := sha256.Sum256([]byte(subSource))
	expectedSub := base64.RawURLEncoding.EncodeToString(hash[:])

	if claims["sub"] != expectedSub {
		t.Errorf("expected sub %s, got %s", expectedSub, claims["sub"])
	}

	if claims["iss"] != issuer {
		t.Errorf("expected iss %s, got %s", issuer, claims["iss"])
	}

	if claims["aud"] != clientID {
		t.Errorf("expected aud %s, got %s", clientID, claims["aud"])
	}

	if claims["nonce"] != nonce {
		t.Errorf("expected nonce %s, got %s", nonce, claims["nonce"])
	}

	// Verify at_hash
	atHash := sha256.Sum256([]byte(accessToken))
	expectedAtHash := base64.RawURLEncoding.EncodeToString(atHash[:len(atHash)/2])
	if claims["at_hash"] != expectedAtHash {
		t.Errorf("expected at_hash %s, got %s", expectedAtHash, claims["at_hash"])
	}
}
