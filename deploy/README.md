# OpenTrusty Auth Plane Deployment

This package contains the OpenTrusty Authentication Plane (authd), which handles OIDC/OAuth2 protocols and user authentication.

## Package Contents

- `opentrusty-authd`: The Go binary.
- `install.sh`: Automated installer script.
- `systemd/`: systemd unit files.
- `.env.example`: Example environment variables.
- `LICENSE`: Apache 2.0 license.

## Installation

1. Extract the tarball:
   ```bash
   tar -xzf opentrusty-auth-<version>-linux-amd64.tar.gz
   cd opentrusty-auth/
   ```

2. Run the installer as root:
   ```bash
   sudo ./install.sh
   ```

3. Configure environment variables in `/etc/opentrusty/auth.env` and `/etc/opentrusty/shared.env`.

4. Start the service:
   ```bash
   sudo systemctl enable --now opentrusty-auth
   ```

## Configuration

The Auth Plane requires connection to the OpenTrusty PostgreSQL database and shared secrets with the Admin Plane. Refer to `.env.example` for detailed variable descriptions.
