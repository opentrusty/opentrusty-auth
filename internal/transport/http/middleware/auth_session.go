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
