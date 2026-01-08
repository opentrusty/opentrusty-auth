# Protocol Scope

This document defines the supported and unsupported protocols in OpenTrusty.

## OAuth2 / OIDC

### Implemented & Supported

-   **Authorization Code Flow** (`response_type=code`)
    -   With PKCE (Proof Key for Code Exchange) - **RECOMMENDED**.
    -   Standard flow for confidential and public clients.
-   **OIDC Discovery**
    -   `/.well-known/openid-configuration`
-   **UserInfo Endpoint**
    -   `/userinfo`
-   **Token Endpoint**
    -   `/oauth2/token`
-   **JWKS Endpoint**
    -   `/oauth2/jwks`

### Explicitly NOT Implemented (Out of Scope)

-   **Implicit Flow** (`response_type=token`) - **FORBIDDEN** (Security risk).
-   **Resource Owner Password Credentials Flow** - **FORBIDDEN**.
-   **Device Authorization Flow** - Not currently implemented.
-   **Client Credentials Flow** - Not currently implemented (Future work).

## Future Additions

Any addition to the supported list requires:
1.  Implementation in `internal/oauth2`.
2.  Update to `001_initial_schema.up.sql` (if new grant types needed).
3.  Update to this document.

## OIDC Scope Semantics

### Canonical Scope Model

Scopes represent **identity claims ONLY**, not permissions or authorization.

| Scope     | Claims Returned                                |
| --------- | ---------------------------------------------- |
| `openid`  | Required for OIDC (sub claim)                  |
| `profile` | name, given_name, family_name, picture, locale |
| `email`   | email, email_verified                          |
| `address` | address claim                                  |
| `phone`   | phone_number, phone_number_verified            |

### Rules

- `openid` is **mandatory** for any OIDC client
- Other scopes are **optional and additive**
- Scopes MUST NOT represent roles or authorization
- Authorization uses `roles → permissions`, not scopes

