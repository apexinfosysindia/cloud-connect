# Cloud Connect
Control plane for ApexOS Cloud Connect: customer signup, billing, admin approvals, and secure remote access orchestration.
## Overview
This repository contains the Cloud Connect control plane:
- Node.js + SQLite backend
- customer portal UI
- admin dashboard
- Razorpay billing flow
- Caddy config
- FRP server config
## Current Behavior
- New users sign up into `payment_pending`.
- Remote access is enabled only for users in `active` or `trial`.
- Paid activation happens after successful Razorpay checkout and verification.
- Free 12-month trials are no longer automatic.
- Free trials are intended to be granted manually from the admin dashboard.
## Architecture
High-level request flow:
`Browser -> Caddy -> FRPS -> FRPC -> ApexOS`
Control plane flow:
`Portal UI -> Express API -> SQLite / Razorpay`
## Repository Layout
```text
.
├── README.md
├── server.js
├── db.js
├── Caddyfile
├── frps.toml
└── public/
    ├── index.html
    └── admin.html
```
## Portal Features
- Customer signup and login
- Razorpay subscription checkout and payment verification
- Razorpay webhook processing
- Admin dashboard for user management
- Manual 365-day trial approval
- Domain verification for Caddy on-demand TLS
- FRP login authorization using access tokens
- Admin fleet visibility for registered SSH tunnel devices
- Device heartbeat tracking (online/offline, local IPs, last seen)
- Device and admin access logs for auditability
- Admin-only connect command generation for remote SSH
- JIT temporary SSH session keys (30 minute default TTL)
## Admin Dashboard
Path:
- `/admin.html`
Capabilities:
- View all users
- Approve a 365-day trial
- Set user status to `active`
- Set user status to `suspended`
- Set user status to `expired`
- Move a user back to `payment_pending`
- View live/offline device fleet state
- Inspect recent device events and admin connect actions
- Generate short-lived admin SSH connect commands per device
Required environment variables:
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- Optional: `ADMIN_SESSION_SECRET`

## Device Fleet API (Internal + Admin)
Internal device endpoints:
- `POST /api/internal/devices/register`
- `POST /api/internal/devices/heartbeat`
- `POST /api/internal/devices/log`
- `POST /api/internal/devices/ssh-sync`

Admin endpoints:
- `GET /api/admin/fleet`
- `GET /api/admin/fleet/:id/logs`
- `POST /api/admin/fleet/:id/connect`

All admin fleet routes require admin bearer auth.
## User Statuses
- `payment_pending`: account created, billing not completed, remote access disabled
- `active`: paid subscription active, remote access enabled
- `trial`: admin-approved free trial, remote access enabled
- `expired`: remote access disabled
- `suspended`: remote access disabled
## Environment Variables
Set these in `.env` on the VPS:
```env
PORT=3000
RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=
RAZORPAY_PLAN_ID=
RAZORPAY_WEBHOOK_SECRET=
ADMIN_EMAIL=
ADMIN_PASSWORD=
ADMIN_SESSION_SECRET=
PORTAL_SESSION_SECRET=
DEVICE_HEARTBEAT_TIMEOUT_SECONDS=45
DEVICE_HEARTBEAT_INTERVAL_SECONDS=20
ADMIN_CONNECT_TOKEN_TTL_MINUTES=10
DEVICE_SSH_POLL_INTERVAL_SECONDS=15
DEVICE_SSH_SESSION_TTL_MINUTES=30
```
## Local Development
Install dependencies:
```bash
npm install
```
Start the portal:
```bash
node server.js
```
The portal serves:
- `/`: customer portal
- `/admin.html`: admin dashboard
SQLite database file:
- `database.sqlite`
## Live VPS Paths
The repo keeps source copies of the edge configs, but the live services use:
- Caddy: `/etc/caddy/Caddyfile`
- FRPS: `/etc/frp/frps.toml`
The repo copies are:
- `Caddyfile`
- `frps.toml`
## Deployment Notes
Typical production restart flow:
```bash
cd /opt/cloud-connect
npm ci --omit=dev
pm2 restart server
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl restart frps
```
## ApexOS Add-on
The separate `apex-cloud-link` add-on repo:
- accepts `subdomain` and `access_token`
- downloads `frpc`
- connects to `cloud.apexinfosys.in:7000`
- registers the customer domain through FRP
- can optionally register into admin fleet tracking and send heartbeats/logs
- can optionally expose SSH over FRP TCP when `ssh_remote_port` is configured
Remote access only succeeds when the portal authorizes the token and the account is `active` or `trial`.

Recommended `apex-cloud-link` options for admin fleet tracking:
- `fleet_reporting_enabled=true`
- `cloud_api_url=https://cloud.apexinfosys.in`
- `device_uid=<stable-device-id>`
- `device_name=<friendly-name>`

Optional admin SSH publish settings:
- `ssh_remote_port=<unique-public-port-on-frps>` (set `0` to disable)
- `ssh_local_port=22`
- `ssh_remote_user=root`
- `ssh_auth_user=root`
- `ssh_authorized_keys_file=` (optional explicit file path)

## JIT SSH Key Flow
1. Admin clicks Connect in fleet UI.
2. Cloud Connect generates one-time SSH keypair when admin key is not provided.
3. Cloud Connect stores public key as a pending device SSH session.
4. `apex-cloud-link` polls `/api/internal/devices/ssh-sync` and updates target `authorized_keys`.
5. Admin connects using provided command and one-time private key.
6. Expired/revoked sessions are removed by addon on sync.
## Billing Notes
- Checkout is Razorpay subscription-based.
- Payment activation is verified both from the browser callback and Razorpay webhooks.
- Pending users do not get their tunnel access token in the portal UI.
- If you want to grant free access, do it from the admin dashboard instead of signup.
## Suggested Git Strategy
Recommended production flow:
- GitHub as source of truth
- GitHub Actions deployment to the VPS over SSH
- Tag stable releases for rollback
- Keep `.env` and `database.sqlite` only on the VPS
## Security Notes
- Do not commit `.env`
- Do not commit `database.sqlite`
- Rotate `webServer.password` in `frps.toml`
- Replace default secrets before production
- Restrict admin credentials to trusted operators only
