package router

import (
"github.com/go-chi/chi/v5"
"github.com/opentrusty/opentrusty-auth/internal/transport/http/handler"
)

func NewRouter(h *handler.Handler) *chi.Mux {
	r := chi.NewRouter()

	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/login", h.Login)
	r.Post("/login", h.PostLogin)
	r.Get("/oauth2/authorize", h.Authorize)

	return r
}
