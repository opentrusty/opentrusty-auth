package middleware

import (
"context"
"net/http"
"github.com/opentrusty/opentrusty-core/session"
)

type SessionConfig struct {
	CookieName string
}

func AuthSession(ss *session.Service, config SessionConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
cookie, err := r.Cookie(config.CookieName)
if err != nil {
next.ServeHTTP(w, r)
return
}

sess, err := ss.Get(r.Context(), cookie.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Inject userID into context
			ctx := context.WithValue(r.Context(), "user_id", sess.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
