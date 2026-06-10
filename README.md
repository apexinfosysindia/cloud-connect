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

- Admin dashboard for user management
- Domain verification for Caddy on-demand TLS
- FRP login authorization using access tokens
- Admin fleet visibility for registered SSH tunnel devices
- Device heartbeat tracking (online/offline, local IPs, last seen)
- Device and admin access logs for auditability

## Device Fleet API (Internal + Admin)

Internal device endpoints:

- `POST /api/internal/devices/register`
- `POST /api/internal/devices/heartbeat`
- `POST /api/internal/devices/log`

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

## Database Migrations

Schema is versioned via SQL files in `migrations/`, one per change, named `NNN_description.sql`. On boot, the migrator reads the `schema_migrations` table, applies any pending files in numeric order inside a transaction each, and fails loudly on error.

To add a schema change:

1. Create the next-numbered file, e.g. `migrations/002_add_foo_column.sql`
2. Write plain DDL/DML — **no** `BEGIN` / `COMMIT` (the runner wraps each file in its own transaction)
3. Restart the server — the migration applies on boot
4. Commit the migration file to git

A pre-existing production database (tables present, no `schema_migrations` row) is automatically stamped with migration 001 on first boot without re-running it.

## Backups

SQLite online backups are produced by `scripts/backup.sh`, which uses the `.backup` command (safe against concurrent writes — never use `cp` on a live SQLite file). Output is gzipped and old backups are rotated.

Run a backup manually:

```bash
npm run backup
```

Environment variables:

- `DATABASE_PATH` — source DB (default: `<repo>/database.sqlite`)
- `BACKUP_DIR` — output directory (default: `<repo>/backups`)
- `BACKUP_RETENTION_DAYS` — delete backups older than N days (default: `14`)
- `BACKUP_SKIP_INTEGRITY` — set to `1` to skip `PRAGMA integrity_check` on the snapshot

Example cron entry (daily at 03:07, logs to file):

```cron
7 3 * * * cd /opt/cloud-connect && BACKUP_DIR=/var/backups/cloud-connect /usr/bin/npm run backup >> /var/log/cloud-connect-backup.log 2>&1
```

Restore a snapshot:

```bash
gunzip -c backups/database-YYYYMMDD-HHMMSS.sqlite.gz > /tmp/restored.sqlite
sqlite3 /tmp/restored.sqlite 'PRAGMA integrity_check'
```

The `backups/` directory is gitignored.

## ApexOS Add-on

The separate `apex-cloud-link` add-on repo:

- accepts `subdomain` and `access_token`
- downloads `frpc`
- connects to `cloud.apexinfosys.in:7000`
- registers the customer domain through FRP
- automatically registers into admin fleet tracking and sends heartbeats/logs
- automatically receives and uses assigned SSH tunnel port from Cloud Connect
  Remote access only succeeds when the portal authorizes the token and the account is `active` or `trial`.

Optional admin SSH publish settings:

- None required. `apex-cloud-link` now auto-registers and receives assigned SSH tunnel port from Cloud Connect.

## Method B: Single-Port Admin SSH (ProxyCommand)

Cloud Connect now generates admin connect commands in explicit dual-key format:

- `ssh -o "ProxyCommand=ssh -i ~/.ssh/jump_key -W %h:%p <jump-user>@<jump-host>" -i ~/.ssh/device_key -p <assigned-port> root@127.0.0.1`

Current internal defaults in code:

- jump host: `cloud.apexinfosys.in`
- jump user: `fleetadmin`
- jump port: `22`
- target host on VPS: `127.0.0.1`

This keeps per-device FRP TCP ports private to the FRPS host and exposes only the jump-host SSH port publicly.

Production requirements:

- Set FRPS `proxyBindAddr = "127.0.0.1"` in `/etc/frp/frps.toml`
- Create a restricted jump user on VPS (example: `fleetadmin`)
- Open only jump-host SSH port (`22` or `443`) in cloud firewall/NSG
- Keep FRP assigned port range closed from public internet

## Google Home

Cloud Connect now includes a private Google Home Cloud-to-Cloud Action:

- OAuth authorize endpoint: `GET /api/google/home/oauth`
- OAuth token endpoint: `POST /api/google/home/token`
- Fulfillment endpoint: `POST /api/google/home/fulfillment`
- Account controls: enable/disable Google Home and entity exposure from customer dashboard

Proactive Homegraph updates (new):

- `requestSync` is triggered on OAuth link, entity inventory changes, and exposure toggles
- `reportStateAndNotification` is sent for changed entity states (debounced)
- SYNC device payload now advertises `willReportState: true` when Homegraph credentials are configured

Online model (production-safe hybrid):

- Effective entity online status uses `device_online && entity_fresh && entity_available`
- `entity_available` comes from addon state (`state != unavailable`)
- `entity_fresh` is time-window based (derived from heartbeat window) to prevent stale entity drift
- Empty or invalid entity sync payloads are ignored (non-destructive)

Internal Homegraph debug/ops endpoints:

- `GET /api/google/home/homegraph-debug`
- `POST /api/internal/google/homegraph/request-sync` (requires `Authorization: Bearer $GOOGLE_HOMEGRAPH_ADMIN_TOKEN`)
- `POST /api/internal/google/homegraph/report-state` (requires `Authorization: Bearer $GOOGLE_HOMEGRAPH_ADMIN_TOKEN`)

Security hardening notes:

- Set strong secrets for `PORTAL_SESSION_SECRET` and `ADMIN_SESSION_SECRET` (minimum 32 chars). The server exits if these are missing.
- Debug endpoints are disabled by default. Enable only when needed with `GOOGLE_DEBUG_ENDPOINTS_ENABLED=1`.
- Set `ALLOWED_CORS_ORIGINS` explicitly for your portal/admin domains.

Addon integration:

- Addon syncs entities via `POST /api/internal/devices/google-home/entities`
- Addon polls queued commands via `POST /api/internal/devices/google-home/commands`
- Addon posts command results via `POST /api/internal/devices/google-home/commands/:id/result`

Cloud-to-Cloud Action entity support:

- `switch.*`, `input_boolean.*`, `automation.*`, `script.*` -> On/Off
- `light.*` -> On/Off + Brightness
- `fan.*` -> On/Off + Fan speed
- `cover.*` -> Open/Close (position)
- `lock.*` -> Lock/Unlock
- `climate.*` -> Thermostat mode + setpoint
- `media_player.*` -> On/Off + Volume/Mute
- `scene.*` and `button.*` -> Scene activate behavior
- `vacuum.*` -> Start/Stop + Pause/Resume
- `sensor.*` (temperature-like) -> ambient temperature state
