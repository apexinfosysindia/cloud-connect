# Cloud Connect
Control plane for ApexOS Cloud Connect: customer signup, billing, admin approvals, and secure remote access orchestration.
## Overview
This repository contains the pieces that power ApexOS remote access:
- `cloud-portal/`: Node.js + SQLite control plane, portal UI, admin dashboard, Razorpay billing flow, Caddy config, and FRP server config.
- `apex-cloud-link/`: ApexOS add-on that connects customer instances back to the FRP edge using an access token.
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
├── cloud-portal/
│   ├── server.js
│   ├── db.js
│   ├── Caddyfile
│   ├── frps.toml
│   └── public/
│       ├── index.html
│       └── admin.html
└── apex-cloud-link/
    ├── config.json
    ├── Dockerfile
    └── rootfs/
```
## Portal Features
- Customer signup and login
- Razorpay subscription checkout and payment verification
- Razorpay webhook processing
- Admin dashboard for user management
- Manual 365-day trial approval
- Domain verification for Caddy on-demand TLS
- FRP login authorization using access tokens
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
Required environment variables:
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- Optional: `ADMIN_SESSION_SECRET`
## User Statuses
- `payment_pending`: account created, billing not completed, remote access disabled
- `active`: paid subscription active, remote access enabled
- `trial`: admin-approved free trial, remote access enabled
- `expired`: remote access disabled
- `suspended`: remote access disabled
## Environment Variables
Set these in `cloud-portal/.env` on the VPS:
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
```
## Local Development
Install dependencies:
```bash
cd cloud-portal
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
- `cloud-portal/database.sqlite`
## Live VPS Paths
The repo keeps source copies of the edge configs, but the live services use:
- Caddy: `/etc/caddy/Caddyfile`
- FRPS: `/etc/frp/frps.toml`
The repo copies are:
- `cloud-portal/Caddyfile`
- `cloud-portal/frps.toml`
## Deployment Notes
Typical production restart flow:
```bash
cd /opt/apex-cloud/cloud-portal
npm ci --omit=dev
pm2 restart server
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl restart frps
```
## ApexOS Add-on
The `apex-cloud-link` add-on:
- accepts `subdomain` and `access_token`
- downloads `frpc`
- connects to `cloud.apexinfosys.in:7000`
- registers the customer domain through FRP
Remote access only succeeds when the portal authorizes the token and the account is `active` or `trial`.
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
