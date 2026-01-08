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
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/opentrusty/opentrusty-auth/internal/oauth2"
	"github.com/opentrusty/opentrusty-auth/internal/oidc"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

// SessionConfig holds session cookie configuration
type SessionConfig struct {
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite
}

// Handler holds Auth Plane HTTP handlers and dependencies
type Handler struct {
	userService    *user.Service
	sessionService *session.Service
	oauth2Service  *oauth2.Service
	tenantService  *tenant.Service
	oidcService    *oidc.Service
	auditLogger    audit.Logger
	sessionConfig  SessionConfig
}

// NewHandler creates a new Auth Plane HTTP handler
func NewHandler(
	userService *user.Service,
	sessionService *session.Service,
	oauth2Service *oauth2.Service,
	tenantService *tenant.Service,
	oidcService *oidc.Service,
	auditLogger audit.Logger,
	sessionConfig SessionConfig,
) *Handler {
	return &Handler{
		userService:    userService,
		sessionService: sessionService,
		oauth2Service:  oauth2Service,
		tenantService:  tenantService,
		oidcService:    oidcService,
		auditLogger:    auditLogger,
		sessionConfig:  sessionConfig,
	}
}

// HealthCheck returns the health status
// @Summary Health Check
// @Description Returns the health status of the auth service
// @Tags System
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status":  "pass",
		"service": "opentrusty-auth",
	})
}

// Discovery returns the OpenID Connect discovery metadata.
// @Summary OIDC Discovery
// @Description Returns the OpenID Connect discovery configuration
// @Tags OIDC
// @Produce json
// @Success 200 {object} map[string]any
// @Router /.well-known/openid-configuration [get]
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	metadata := h.oidcService.GetDiscoveryMetadata()
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, http.StatusOK, metadata)
}

// JWKS returns the JSON Web Key Set for token signature verification.
// @Summary JWKS
// @Description Returns the JSON Web Key Set
// @Tags OIDC
// @Produce json
// @Success 200 {object} map[string]any
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.oidcService.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, http.StatusOK, jwks)
}

// OIDCLogin renders the interactive login page for the end-user.
func (h *Handler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Sign In - OpenTrusty</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 320px; }
        h1 { margin-top: 0; color: #1a1a1a; font-size: 1.5rem; }
        .subtitle { color: #666; font-size: 0.875rem; margin-bottom: 1.5rem; }
        input { width: 100%; padding: 0.75rem; margin: 0.5rem 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 0.75rem; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; margin-top: 1rem; }
        button:hover { background: #1d4ed8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Sign In</h1>
        <p class="subtitle">OpenTrusty Identity Provider</p>
        <form method="POST" action="/login{{if .ReturnTo}}?return_to={{.ReturnTo}}{{end}}">
            <input type="email" name="email" placeholder="Email" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`

	t, _ := template.New("login").Parse(tmpl)
	data := struct {
		ReturnTo string
	}{
		ReturnTo: r.URL.Query().Get("return_to"),
	}
	t.Execute(w, data)
}

// OIDCPostLogin handles the submission of user credentials
func (h *Handler) OIDCPostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	u, err := h.userService.Authenticate(r.Context(), email, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	sess, err := h.sessionService.Create(r.Context(), nil, u.ID, getIPAddress(r), r.UserAgent(), "auth")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	h.setSessionCookie(w, sess.ID)

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// Authorize handles OAuth2 authorization requests
// @Summary OAuth2 Authorize
// @Description Entry point for OAuth2/OIDC authorization flow
// @Tags OAuth2
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param response_type query string true "Response Type"
// @Param scope query string true "Scope"
// @Param state query string false "State"
// @Param nonce query string false "Nonce"
// @Success 302 {string} string "Redirect to login or consent"
// @Router /oauth2/authorize [get]
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	req := &oauth2.AuthorizeRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		ResponseType:        query.Get("response_type"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}

	// Note: tenantID in Auth plane is usually inferred from client or hostname
	tenantID := "" // Search across all tenants if not specified

	slog.Info("Authorize request validation", "client_id", req.ClientID, "tenant_id", tenantID)

	c, err := h.oauth2Service.ValidateAuthorizeRequest(r.Context(), tenantID, req)
	if err != nil {
		slog.Error("Authorize request validation failed", "error", err)
		h.respondOAuthError(w, err)
		return
	}

	slog.Info("Authorize request validated", "client_id", c.ClientID, "client_tenant", c.TenantID)

	// Check authentication
	userID := h.getUserID(r)
	if userID == "" {
		slog.Info("User not authenticated, redirecting to login", "return_to", r.URL.String())
		// Redirect to login with return_to pointing back here
		loginURL := fmt.Sprintf("/login?return_to=%s", template.URLQueryEscaper(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	consentURL := fmt.Sprintf("/consent?%s", r.URL.Query().Encode())
	http.Redirect(w, r, consentURL, http.StatusFound)
}

// OIDCConsent renders the consent page
func (h *Handler) OIDCConsent(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>Authorize App - OpenTrusty</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 400px; }
        h1 { margin-top: 0; color: #1a1a1a; font-size: 1.5rem; }
        .scope-list { background: #f9fafb; padding: 1rem; border-radius: 4px; margin: 1rem 0; font-size: 0.875rem; color: #374151; }
        .actions { display: flex; gap: 1rem; margin-top: 1.5rem; }
        .btn { flex: 1; padding: 0.75rem; border-radius: 4px; cursor: pointer; font-weight: bold; text-align: center; text-decoration: none; border: none; }
        .btn-approve { background: #2563eb; color: white; }
        .btn-cancel { background: #e5e7eb; color: #374151; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorize Access</h1>
        <p>The application is requesting access to your OpenTrusty account.</p>
        <div class="scope-list">
            <strong>Requested Scopes:</strong><br>
            {{.Scope}}
        </div>
        <form method="POST" action="/consent">
            {{range $key, $values := .Params}}
                {{range $value := $values}}
                    <input type="hidden" name="{{$key}}" value="{{$value}}">
                {{end}}
            {{end}}
            <div class="actions">
                <button type="submit" name="consent" value="approve" class="btn btn-approve">Approve</button>
                <button type="submit" name="consent" value="cancel" class="btn btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</body>
</html>`

	t, _ := template.New("consent").Parse(tmpl)
	data := struct {
		Scope  string
		Params map[string][]string
	}{
		Scope:  r.URL.Query().Get("scope"),
		Params: r.URL.Query(),
	}
	t.Execute(w, data)
}

// OIDCPostConsent handles consent submission
func (h *Handler) OIDCPostConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	consent := r.FormValue("consent")
	if consent != "approve" {
		// Handle denial (simplified: redirect back to client with error)
		redirectURI := r.Form.Get("redirect_uri")
		state := r.Form.Get("state")
		target := fmt.Sprintf("%s?error=access_denied&state=%s", redirectURI, state)
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	req := &oauth2.AuthorizeRequest{
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		ResponseType:        r.Form.Get("response_type"),
		Scope:               r.Form.Get("scope"),
		State:               r.Form.Get("state"),
		Nonce:               r.Form.Get("nonce"),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
	}

	code, err := h.oauth2Service.CreateAuthorizationCode(r.Context(), req, userID)
	if err != nil {
		h.respondOAuthError(w, err)
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", req.RedirectURI, code.Code, req.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Token handles OAuth2 token requests
// @Summary OAuth2 Token
// @Description Exchange authorization code or refresh token for access tokens
// @Tags OAuth2
// @Accept x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant Type"
// @Param code formData string false "Authorization Code"
// @Param redirect_uri formData string false "Redirect URI"
// @Param client_id formData string false "Client ID"
// @Param client_secret formData string false "Client Secret"
// @Param refresh_token formData string false "Refresh Token"
// @Success 200 {object} oauth2.TokenResponse
// @Failure 400 {object} oauth2.Error
// @Router /oauth2/token [post]
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	req := &oauth2.TokenRequest{
		TenantID:     "", // Search across all tenants
		GrantType:    r.Form.Get("grant_type"),
		Code:         r.Form.Get("code"),
		RedirectURI:  r.Form.Get("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.Form.Get("code_verifier"),
		RefreshToken: r.Form.Get("refresh_token"),
		Scope:        r.Form.Get("scope"),
	}

	resp, err := h.oauth2Service.ExchangeCodeForToken(r.Context(), req)
	if err != nil {
		h.respondOAuthError(w, err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, resp)
}

// Helpers

func (h *Handler) getUserID(r *http.Request) string {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok {
		return ""
	}
	return userID
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Fprintf(w, `{"error": "failed to encode response"}`)
	}
}

func (h *Handler) respondOAuthError(w http.ResponseWriter, err error) {
	if oauthErr, ok := err.(*oauth2.Error); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(oauthErr)
		return
	}
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func getIPAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionConfig.CookieName,
		Value:    sessionID,
		Path:     h.sessionConfig.CookiePath,
		Secure:   h.sessionConfig.CookieSecure,
		HttpOnly: true,
		SameSite: h.sessionConfig.CookieSameSite,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}
