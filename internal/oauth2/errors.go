// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package oauth2

import "fmt"

// Protocol error codes
const (
	ErrInvalidRequest          = "invalid_request"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrInvalidScope            = "invalid_scope"
	ErrAccessDenied            = "access_denied"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
)

// Error represents an OAuth2 protocol error (RFC 6749 Section 4.1.2.1 / 5.2)
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// NewError creates a new OAuth2 error
func NewError(code, description string) *Error {
	return &Error{
		Code:        code,
		Description: description,
	}
}
