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

package oauth2

import (
	"errors"

	"github.com/opentrusty/opentrusty-core/client"
)

// Domain errors (Protocol Specific)
var (
	ErrCodeExpired     = errors.New("authorization code expired")
	ErrCodeAlreadyUsed = errors.New("authorization code already used")
	ErrCodeNotFound    = errors.New("authorization code not found")
	ErrTokenExpired    = errors.New("token expired")
	ErrTokenRevoked    = errors.New("token revoked")
	ErrTokenNotFound   = errors.New("token not found")
)

// OIDC Standard Scope Constants
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeAddress = "address"
	ScopePhone   = "phone"
)

// Aliases for core models
type AuthorizationCode = client.AuthorizationCode
type AccessToken = client.AccessToken
type RefreshToken = client.RefreshToken

// AuthorizationCodeRepository defines the interface for authorization code persistence
type AuthorizationCodeRepository interface {
	Create(code *AuthorizationCode) error
	GetByCode(code string) (*AuthorizationCode, error)
	MarkAsUsed(code string) error
	Delete(code string) error
	DeleteExpired() error
}

// AccessTokenRepository defines the interface for access token persistence
type AccessTokenRepository interface {
	Create(token *AccessToken) error
	GetByTokenHash(tokenHash string) (*AccessToken, error)
	Revoke(tokenHash string) error
	DeleteExpired() error
}

// RefreshTokenRepository defines the interface for refresh token persistence
type RefreshTokenRepository interface {
	Create(token *RefreshToken) error
	GetByTokenHash(tokenHash string) (*RefreshToken, error)
	Revoke(tokenHash string) error
	DeleteExpired() error
}
