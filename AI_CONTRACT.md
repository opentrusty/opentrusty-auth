# AI_CONTRACT — opentrusty-auth

## Scope of Responsibility
- OAuth2 and OpenID Connect protocol execution.
- Server-rendered Login and Consent UI.
- Token issuance and signing.
- Authentication session management (cookie-based).

## Explicit Non-Goals
- **NO Admin Queries**: Cannot query full user lists or system-wide audit logs.
- **NO Bootstrap**: Does not handle initial system setup.
- **NO Direct User Mutation**: Must use core services for authenticated profile updates only.

## Allowed Dependencies
- `github.com/opentrusty/opentrusty-core`

## Forbidden Dependencies
- **NO dependencies** on `opentrusty-admin` or `opentrusty-control-panel`.

## Change Discipline
- Changes to token claims or OIDC discovery MUST update docs/oidc/capabilities.md.
- UI flow changes MUST be verified against security session invariants.

## Invariants
- **Audit Writing**: MUST log all security-sensitive protocol events.
- **Protocol Strictness**: redirect_uri exact match as per RFC 6749.
