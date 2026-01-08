// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/client"
)

// Mock repos for oauth2
type mockClientRepo struct {
	client.ClientRepository
	clients map[string]*client.Client
}

func (m *mockClientRepo) GetByClientID(ctx context.Context, tenantID, clientID string) (*client.Client, error) {
	for _, c := range m.clients {
		if c.TenantID == tenantID && c.ClientID == clientID {
			return c, nil
		}
	}
	return nil, client.ErrClientNotFound
}

type mockCodeRepo struct {
	AuthorizationCodeRepository
	codes map[string]*AuthorizationCode
}

func (m *mockCodeRepo) Create(code *AuthorizationCode) error {
	m.codes[code.Code] = code
	return nil
}

func (m *mockCodeRepo) GetByCode(code string) (*AuthorizationCode, error) {
	c, ok := m.codes[code]
	if !ok {
		return nil, NewError(ErrInvalidGrant, "code not found")
	}
	return c, nil
}

func (m *mockCodeRepo) MarkAsUsed(code string) error {
	c, ok := m.codes[code]
	if !ok {
		return NewError(ErrInvalidGrant, "code not found")
	}
	c.IsUsed = true
	return nil
}

type mockAccessRepo struct {
	AccessTokenRepository
}

func (m *mockAccessRepo) Create(token *AccessToken) error { return nil }

type mockRefreshRepo struct {
	RefreshTokenRepository
}

func (m *mockRefreshRepo) Create(token *RefreshToken) error { return nil }

type mockAuditLogger struct{}

func (m *mockAuditLogger) Log(ctx context.Context, event audit.Event) {}

func TestValidateAuthorizeRequest(t *testing.T) {
	c := &client.Client{
		ClientID:      "client-1",
		TenantID:      "t1",
		IsActive:      true,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedScopes: []string{"openid", "profile"},
	}

	clientRepo := &mockClientRepo{
		clients: map[string]*client.Client{c.ClientID: c},
	}

	svc := NewService(clientRepo, &mockCodeRepo{}, &mockAccessRepo{}, &mockRefreshRepo{}, &mockAuditLogger{}, nil, time.Minute, time.Minute, time.Minute, make([]byte, 32))

	tests := []struct {
		name    string
		req     *AuthorizeRequest
		wantErr bool
		errCode string
	}{
		{
			name: "valid request",
			req: &AuthorizeRequest{
				ClientID:     "client-1",
				RedirectURI:  "https://app.example.com/callback",
				ResponseType: "code",
			},
			wantErr: false,
		},
		{
			name: "invalid client_id",
			req: &AuthorizeRequest{
				ClientID:     "wrong-client",
				RedirectURI:  "https://app.example.com/callback",
				ResponseType: "code",
			},
			wantErr: true,
			errCode: ErrInvalidRequest,
		},
		{
			name: "invalid redirect_uri",
			req: &AuthorizeRequest{
				ClientID:     "client-1",
				RedirectURI:  "https://malicious.com",
				ResponseType: "code",
			},
			wantErr: true,
			errCode: ErrInvalidRequest,
		},
		{
			name: "unsupported response_type",
			req: &AuthorizeRequest{
				ClientID:     "client-1",
				RedirectURI:  "https://app.example.com/callback",
				ResponseType: "token",
			},
			wantErr: true,
			errCode: ErrUnsupportedGrantType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateAuthorizeRequest(context.Background(), "t1", tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthorizeRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if oauthErr, ok := err.(*Error); ok {
					if oauthErr.Code != tt.errCode {
						t.Errorf("expected error code %s, got %s", tt.errCode, oauthErr.Code)
					}
				}
			}
		})
	}
}

func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		want      bool
	}{
		{
			name:      "plain match",
			challenge: "secret",
			method:    "plain",
			verifier:  "secret",
			want:      true,
		},
		{
			name:      "plain mismatch",
			challenge: "secret",
			method:    "plain",
			verifier:  "wrong",
			want:      false,
		},
		{
			name:      "S256 match",
			challenge: "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", // SHA256 of "abc"
			method:    "S256",
			verifier:  "abc",
			want:      true,
		},
		{
			name:      "S256 mismatch",
			challenge: "E9Mel95mSRpNSA9E_9NSh08U04R6Wz9P99I_R9N-E9A",
			method:    "S256",
			verifier:  "wrong",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validatePKCE(tt.challenge, tt.method, tt.verifier); got != tt.want {
				t.Errorf("validatePKCE() = %v, want %v", got, tt.want)
			}
		})
	}
}
