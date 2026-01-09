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

	// Wrap with logging, sessions and CSRF
	handler := http.Handler(mux)
	handler = loggingMiddleware(handler)
	handler = middleware.CSRF(h.sessionConfig.CSRFEnabled)(handler)
	handler = middleware.AuthSession(h.sessionService, middleware.SessionConfig{
		CookieName:     h.sessionConfig.CookieName,
		CookieDomain:   h.sessionConfig.CookieDomain,
		CookiePath:     h.sessionConfig.CookiePath,
		CookieSecure:   h.sessionConfig.CookieSecure,
		CookieHTTPOnly: h.sessionConfig.CookieHTTPOnly,
		CookieSameSite: h.sessionConfig.CookieSameSite,
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
