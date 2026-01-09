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

## Deployment

For production-grade deployment, we recommend using the pre-built binaries available in the [GitHub Releases](https://github.com/opentrusty/opentrusty-auth/releases).

Detailed instructions are available in the [Canonical Deployment Guide](https://github.com/opentrusty/opentrusty-core/blob/main/DEPLOYMENT.md) and the `README.md` included in each release package.

## License


Apache-2.0
