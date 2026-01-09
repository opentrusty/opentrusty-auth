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

package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opentrusty/opentrusty-auth/internal/config"
	"github.com/opentrusty/opentrusty-auth/internal/oauth2"
	"github.com/opentrusty/opentrusty-auth/internal/oidc"
	transportHTTP "github.com/opentrusty/opentrusty-auth/internal/transport/http"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/store/postgres"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	// 0. Connect to DB
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 1. Initialize Core dependencies
	userRepo := postgres.NewUserRepository(db)
	hasher := user.NewPasswordHasher(65536, 1, 1, 16, 32)
	auditRepo := postgres.NewAuditRepository(db)
	auditLogger := audit.NewRepositoryLogger(auditRepo)

	userService := user.NewService(userRepo, hasher, auditLogger, 5, 15*time.Minute, cfg.IdentitySecret)

	sessionRepo := postgres.NewSessionRepository(db)
	sessionService := session.NewService(sessionRepo, 24*time.Hour, 1*time.Hour)

	tenantRepo := postgres.NewTenantRepository(db)
	membershipRepo := postgres.NewMembershipRepository(db)
	roleRepo := postgres.NewTenantRoleRepository(db)
	authzRepo := postgres.NewPolicyAssignmentRepository(db)

	clientRepo := postgres.NewClientRepository(db)
	codeRepo := postgres.NewAuthorizationCodeRepository(db)
	accessRepo := postgres.NewAccessTokenRepository(db)
	refreshRepo := postgres.NewRefreshTokenRepository(db)

	tenantService := tenant.NewService(
		tenantRepo,
		roleRepo,
		authzRepo,
		userService,
		clientRepo,
		membershipRepo,
		auditLogger,
	)

	// 2. Initialize Auth plane services
	oidcService, _ := oidc.NewService("http://localhost:8080")

	oauth2Service := oauth2.NewService(
		clientRepo,
		codeRepo,
		accessRepo,
		refreshRepo,
		auditLogger,
		oidcService,
		5*time.Minute,
		1*time.Hour,
		24*time.Hour,
		[]byte(cfg.SessionSecret),
	)

	// 3. Initialize Transport
	handler := transportHTTP.NewHandler(
		userService,
		sessionService,
		oauth2Service,
		tenantService,
		oidcService,
		auditLogger,
		transportHTTP.SessionConfig{
			CookieName:     cfg.CookieName,
			CookiePath:     "/",
			CookieDomain:   cfg.CookieDomain,
			CookieSecure:   cfg.CookieSecure,
			CookieHTTPOnly: cfg.CookieHTTPOnly,
			CookieSameSite: cfg.GetSameSite(),
		},
	)

	router := transportHTTP.NewRouter(handler)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			stop()
		}
	}()

	slog.Info("authd ready", "addr", server.Addr, "db", "connected")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down authd")
	server.Shutdown(ctx)
}
