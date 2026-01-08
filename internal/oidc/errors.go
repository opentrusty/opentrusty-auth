// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import "fmt"

// OIDC error codes
const (
	ErrInvalidRequest          = "invalid_request"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrAccessDenied            = "access_denied"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
	ErrLoginRequired           = "login_required"
	ErrInteractionRequired     = "interaction_required"
)

// Error represents an OIDC protocol error
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// NewError creates a new OIDC error
func NewError(code, description string) *Error {
	return &Error{
		Code:        code,
		Description: description,
	}
}
