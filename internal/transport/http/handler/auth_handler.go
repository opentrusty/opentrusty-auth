package handler

import (
"fmt"
"html/template"
"net/http"
"github.com/opentrusty/opentrusty-core/user"
"github.com/opentrusty/opentrusty-core/session"
"github.com/opentrusty/opentrusty-auth/internal/oauth2"
"github.com/opentrusty/opentrusty-auth/internal/oidc"
)

type Handler struct {
	userService    *user.Service
	sessionService *session.Service
	oauth2Service  *oauth2.Service
	oidcService    *oidc.Service
	cookieName     string
}

func NewHandler(us *user.Service, ss *session.Service, oa *oauth2.Service, oi *oidc.Service, cookieName string) *Handler {
	return &Handler{
		userService:    us,
		sessionService: ss,
		oauth2Service:  oa,
		oidcService:    oi,
		cookieName:     cookieName,
	}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	tmpl := `<html><body><h1>Login</h1><form method="POST"><input name="email"><input type="password" name="password"><button>Login</button></form></body></html>`
	t, _ := template.New("login").Parse(tmpl)
	t.Execute(w, nil)
}

func (h *Handler) PostLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	pass := r.FormValue("password")
	u, err := h.userService.Authenticate(r.Context(), email, pass)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sess, _ := h.sessionService.Create(r.Context(), nil, u.ID, r.RemoteAddr, r.UserAgent(), "auth")
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: sess.ID, Path: "/"})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	m := h.oidcService.GetDiscoveryMetadata()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"issuer\":\"%s\"}", m.Issuer)
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Logic here
}
