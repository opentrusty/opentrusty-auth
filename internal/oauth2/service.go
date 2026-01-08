// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/id"
)

// OIDCProvider defines the interface for OIDC integration.
//
// Purpose: Abstraction for identity token generation.
// Domain: OIDC
type OIDCProvider interface {
	GenerateIDToken(userID, tenantID, clientID, nonce, accessToken string) (string, error)
}

// Service provides OAuth2 business logic.
//
// Purpose: Core execution engine for OAuth2 protocol flows.
// Domain: OAuth2
type Service struct {
	clientRepo   client.ClientRepository
	codeRepo     AuthorizationCodeRepository
	accessRepo   AccessTokenRepository
	refreshRepo  RefreshTokenRepository
	auditLogger  audit.Logger
	oidcProvider OIDCProvider

	authCodeLifetime     time.Duration
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	encryptionKey        []byte
}

// NewService creates a new OAuth2 service.
//
// Purpose: Constructor for the OAuth2 protocol engine.
// Domain: OAuth2
// Audited: No
// Errors: Connectivity and configuration errors
func NewService(
	clientRepo client.ClientRepository,
	codeRepo AuthorizationCodeRepository,
	accessRepo AccessTokenRepository,
	refreshRepo RefreshTokenRepository,
	auditLogger audit.Logger,
	oidcProvider OIDCProvider,
	authCodeLifetime time.Duration,
	accessTokenLifetime time.Duration,
	refreshTokenLifetime time.Duration,
	keyEncryptionKey []byte,
) *Service {
	if len(keyEncryptionKey) != 32 {
		panic("keyEncryptionKey must be exactly 32 bytes")
	}

	return &Service{
		clientRepo:           clientRepo,
		codeRepo:             codeRepo,
		accessRepo:           accessRepo,
		refreshRepo:          refreshRepo,
		auditLogger:          auditLogger,
		oidcProvider:         oidcProvider,
		authCodeLifetime:     authCodeLifetime,
		accessTokenLifetime:  accessTokenLifetime,
		refreshTokenLifetime: refreshTokenLifetime,
		encryptionKey:        keyEncryptionKey,
	}
}

// AuthorizeRequest represents an OAuth2 authorization request.
//
// Purpose: Container for incoming /authorize request parameters.
// Domain: OAuth2
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// TokenRequest represents an OAuth2 token request.
//
// Purpose: Container for incoming /token request parameters.
// Domain: OAuth2
type TokenRequest struct {
	TenantID     string
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// TokenResponse represents an OAuth2 token response.
//
// Purpose: Standardized fields returned after successful token exchange.
// Domain: OAuth2
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ValidateAuthorizeRequest validates an authorization request
func (s *Service) ValidateAuthorizeRequest(ctx context.Context, tenantID string, req *AuthorizeRequest) (*client.Client, error) {
	c, err := s.clientRepo.GetByClientID(ctx, tenantID, req.ClientID)
	if err != nil {
		return nil, NewError(ErrInvalidRequest, "invalid client_id")
	}

	if !c.IsActive {
		return nil, NewError(ErrInvalidRequest, "client is disabled")
	}

	if !c.ValidateRedirectURI(req.RedirectURI) {
		return nil, NewError(ErrInvalidRequest, "invalid redirect_uri")
	}

	if req.ResponseType != "code" {
		return nil, NewError(ErrUnsupportedGrantType, "response_type must be 'code'")
	}

	if req.Scope != "" && !c.ValidateScope(req.Scope) {
		return nil, NewError(ErrInvalidScope, "invalid scope")
	}

	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "plain" && req.CodeChallengeMethod != "S256" {
			return nil, NewError(ErrInvalidRequest, "transform algorithm not supported")
		}
	}

	return c, nil
}

// CreateAuthorizationCode creates a new authorization code
func (s *Service) CreateAuthorizationCode(ctx context.Context, req *AuthorizeRequest, userID string) (*AuthorizationCode, error) {
	code := &AuthorizationCode{
		ID:                  id.NewUUIDv7(),
		Code:                generateAuthorizationCode(),
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		IsUsed:              false,
		CreatedAt:           time.Now(),
	}

	if err := s.codeRepo.Create(code); err != nil {
		slog.Error("Failed to persist authorization code", "error", err, "code_id", code.ID)
		return nil, NewError(ErrServerError, "failed to persist authorization code")
	}

	return code, nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens
func (s *Service) ExchangeCodeForToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	c, err := s.ValidateClientCredentials(ctx, req.TenantID, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if req.GrantType != "authorization_code" {
		return nil, NewError(ErrUnsupportedGrantType, "grant_type must be 'authorization_code'")
	}

	code, err := s.codeRepo.GetByCode(req.Code)
	if err != nil {
		return nil, NewError(ErrInvalidGrant, "authorization code not found")
	}

	if code.IsUsed {
		return nil, NewError(ErrInvalidGrant, "authorization code already used")
	}

	if code.IsExpired() {
		return nil, NewError(ErrInvalidGrant, "authorization code expired")
	}

	if code.ClientID != req.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	if code.RedirectURI != req.RedirectURI {
		return nil, NewError(ErrInvalidGrant, "redirect_uri mismatch")
	}

	if code.CodeChallenge != "" {
		if !validatePKCE(code.CodeChallenge, code.CodeChallengeMethod, req.CodeVerifier) {
			return nil, NewError(ErrInvalidGrant, "invalid code_verifier")
		}
	}

	if err := s.codeRepo.MarkAsUsed(req.Code); err != nil {
		return nil, NewError(ErrServerError, "failed to invalidate authorization code")
	}

	rawAccessToken := generateToken()
	accessToken := &AccessToken{
		ID:        id.NewUUIDv7(),
		TenantID:  c.TenantID,
		TokenHash: hashToken(rawAccessToken),
		ClientID:  c.ClientID,
		UserID:    code.UserID,
		Scope:     code.Scope,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Duration(c.AccessTokenLifetime) * time.Second),
		IsRevoked: false,
		CreatedAt: time.Now(),
	}

	if err := s.accessRepo.Create(accessToken); err != nil {
		return nil, NewError(ErrServerError, "failed to issue access token")
	}

	var refreshToken string
	allowedRefresh := false
	for _, gt := range c.GrantTypes {
		if gt == "refresh_token" {
			allowedRefresh = true
			break
		}
	}

	if allowedRefresh {
		rawRefreshToken := generateToken()
		rt := &RefreshToken{
			ID:            id.NewUUIDv7(),
			TenantID:      c.TenantID,
			TokenHash:     hashToken(rawRefreshToken),
			AccessTokenID: accessToken.ID,
			ClientID:      c.ClientID,
			UserID:        code.UserID,
			Scope:         code.Scope,
			ExpiresAt:     time.Now().Add(time.Duration(c.RefreshTokenLifetime) * time.Second),
			IsRevoked:     false,
			CreatedAt:     time.Now(),
		}
		if err := s.refreshRepo.Create(rt); err != nil {
			slog.Error("Failed to persist refresh token", "error", err)
		} else {
			refreshToken = rawRefreshToken
		}
	}

	var idToken string
	if s.oidcProvider != nil && containsScope(code.Scope, "openid") {
		it, err := s.oidcProvider.GenerateIDToken(code.UserID, c.TenantID, c.ClientID, code.Nonce, rawAccessToken)
		if err == nil {
			idToken = it
		}
	}

	s.auditLogger.Log(ctx, audit.Event{
		Type:     audit.TypeTokenIssued,
		TenantID: c.TenantID,
		ActorID:  code.UserID,
		Resource: audit.ResourceToken,
		Metadata: map[string]any{
			"client_id": c.ClientID,
			"scope":     code.Scope,
			"has_rt":    refreshToken != "",
			"has_it":    idToken != "",
		},
	})

	return &TokenResponse{
		AccessToken:  rawAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    c.AccessTokenLifetime,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        code.Scope,
	}, nil
}

// ValidateClientCredentials validates client credentials
func (s *Service) ValidateClientCredentials(ctx context.Context, tenantID string, clientID, clientSecret string) (*client.Client, error) {
	c, err := s.clientRepo.GetByClientID(ctx, tenantID, clientID)
	if err != nil {
		return nil, NewError(ErrInvalidClient, "invalid client credentials")
	}

	if !c.IsActive {
		return nil, NewError(ErrInvalidClient, "client is disabled")
	}

	if c.ClientSecretHash == "" {
		return c, nil
	}

	secretHash := hashClientSecret(clientSecret)
	if secretHash != c.ClientSecretHash {
		return nil, NewError(ErrInvalidClient, "invalid client credentials")
	}

	return c, nil
}

// Helpers (Internal)

func validatePKCE(challenge, method, verifier string) bool {
	if method == "" || method == "plain" {
		return challenge == verifier
	}
	if method == "S256" {
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return challenge == computed
	}
	return false
}

func containsScope(scope, target string) bool {
	parts := strings.Split(scope, " ")
	for _, part := range parts {
		if part == target {
			return true
		}
	}
	return false
}

func generateAuthorizationCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func hashClientSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *Service) GetClientByClientID(ctx context.Context, tenantID, clientID string) (*client.Client, error) {
	return s.clientRepo.GetByClientID(ctx, tenantID, clientID)
}

func (s *Service) RevokeRefreshToken(ctx context.Context, token string, clientID string) error {
	rt, err := s.refreshRepo.GetByTokenHash(hashToken(token))
	if err != nil {
		return ErrTokenNotFound
	}
	if rt.ClientID != clientID {
		return NewError(ErrInvalidClient, "client_id mismatch")
	}
	return s.refreshRepo.Revoke(hashToken(token))
}

func (s *Service) RefreshAccessToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	c, err := s.ValidateClientCredentials(ctx, req.TenantID, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	rt, err := s.refreshRepo.GetByTokenHash(hashToken(req.RefreshToken))
	if err != nil {
		return nil, NewError(ErrInvalidGrant, "refresh token not found")
	}

	if rt.IsRevoked {
		return nil, NewError(ErrInvalidGrant, "refresh token revoked")
	}

	if rt.IsExpired() {
		return nil, NewError(ErrInvalidGrant, "refresh token expired")
	}

	if rt.ClientID != c.ClientID {
		return nil, NewError(ErrInvalidGrant, "client_id mismatch")
	}

	rawAccessToken := generateToken()
	accessToken := &AccessToken{
		ID:        id.NewUUIDv7(),
		TenantID:  c.TenantID,
		TokenHash: hashToken(rawAccessToken),
		ClientID:  c.ClientID,
		UserID:    rt.UserID,
		Scope:     rt.Scope,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Duration(c.AccessTokenLifetime) * time.Second),
		IsRevoked: false,
		CreatedAt: time.Now(),
	}

	if err := s.accessRepo.Create(accessToken); err != nil {
		return nil, NewError(ErrServerError, "failed to issue access token")
	}

	return &TokenResponse{
		AccessToken:  rawAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    c.AccessTokenLifetime,
		RefreshToken: req.RefreshToken,
		Scope:        rt.Scope,
	}, nil
}
