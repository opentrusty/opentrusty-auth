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

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opentrusty/opentrusty-auth/internal/oauth2"
	"github.com/opentrusty/opentrusty-auth/internal/oidc"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/store/postgres"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

func TestAuthFlow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db, cleanup := postgres.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	auditLogger := audit.NewSlogLogger()

	// Setup Repos
	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)
	membershipRepo := postgres.NewMembershipRepository(db)
	roleRepo := postgres.NewTenantRoleRepository(db)
	authzRepo := postgres.NewPolicyAssignmentRepository(db)
	clientRepo := postgres.NewClientRepository(db)
	codeRepo := postgres.NewAuthorizationCodeRepository(db)
	accessRepo := postgres.NewAccessTokenRepository(db)
	refreshRepo := postgres.NewRefreshTokenRepository(db)

	// Setup Services
	hasher := user.NewPasswordHasher(65536, 1, 1, 16, 32)
	userService := user.NewService(userRepo, hasher, auditLogger, 5, 15*time.Minute, "test-key")
	sessionService := session.NewService(sessionRepo, 24*time.Hour, 1*time.Hour)
	tenantService := tenant.NewService(tenantRepo, roleRepo, authzRepo, userService, clientRepo, membershipRepo, auditLogger)
	oidcService, _ := oidc.NewService("http://localhost:8080")
	oauth2Service := oauth2.NewService(clientRepo, codeRepo, accessRepo, refreshRepo, auditLogger, oidcService, 5*time.Minute, 1*time.Hour, 24*time.Hour, make([]byte, 32))

	handler := NewHandler(userService, sessionService, oauth2Service, tenantService, oidcService, auditLogger, SessionConfig{CookieName: "session_id"})

	// 1. Seed Data (Client)
	c := &client.Client{
		ID:            "00000000-0000-0000-0000-000000000301",
		ClientID:      "client-1",
		TenantID:      "00000000-0000-0000-0000-000000000001",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"http://localhost:3000/callback"},
		AllowedScopes: []string{"openid", "profile"},
	}
	_ = clientRepo.Create(ctx, c)

	// 2. Test Token Request (Mocking valid grant for now to test the handler wiring)
	t.Run("Token Exchange - ErrorCase (Invalid Client)", func(t *testing.T) {
		body := `grant_type=authorization_code&code=abc&client_id=wrong-client`
		req, _ := http.NewRequest("POST", "/oauth2/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.Token(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rr.Code)
		}
	})
}
