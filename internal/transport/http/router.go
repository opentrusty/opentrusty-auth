// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/opentrusty/opentrusty-auth/internal/transport/http/middleware"
)

// Router handles Auth Plane routing
func NewRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", h.HealthCheck)
	mux.HandleFunc("/.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("/jwks.json", h.JWKS)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.OIDCPostLogin(w, r)
		} else {
			h.OIDCLogin(w, r)
		}
	})
	mux.HandleFunc("/consent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.OIDCPostConsent(w, r)
		} else {
			h.OIDCConsent(w, r)
		}
	})
	mux.HandleFunc("/oauth2/authorize", h.Authorize)
	mux.HandleFunc("/oauth2/token", h.Token)

	// Wrap with logging and sessions
	handler := http.Handler(mux)
	handler = loggingMiddleware(handler)
	handler = middleware.AuthSession(h.sessionService, middleware.SessionConfig{
		CookieName: h.sessionConfig.CookieName,
	})(handler)

	return handler
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		slog.Info("http_request_start", "method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
		next.ServeHTTP(w, r)
		slog.Info("http_request_end", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	})
}
