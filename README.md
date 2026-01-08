# OpenTrusty Auth

OpenTrusty Auth is the **Authentication & OIDC Data Plane** of the OpenTrusty Identity Platform.

It is responsible for end-user authentication, session issuance, and execution of the OAuth2 and OpenID Connect protocols.

## Role & Responsibility

- **OIDC Gateway**: Implements the OIDC discovery, authorization, token, and userinfo endpoints.
- **End-User UI**: Server-side rendered (SSR) templates for login, consent, and account recovery.
- **Session Management**: Issues and validates primary user sessions for browser-based access.
- **Architecture**: Depends strictly on `opentrusty-core`. Has NO knowledge of the Admin Plane APIs.

## Requirements

- PostgreSQL (via `DATABASE_URL`)
- OpenTrusty Core (Go module)

## Getting Started

1. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
2. Build the daemon:
   ```bash
   make build
   ```
3. Run the service:
   ```bash
   ./authd
   ```

## License

MIT
