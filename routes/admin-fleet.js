const express = require('express');

module.exports = function ({ dbGet, dbAll, utils, auth, device }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // Escape LIKE wildcards so a literal % or _ in a search term is matched as
    // text rather than as a wildcard.
    function likePattern(term) {
        return `%${term.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    }

    router.get(
        '/api/admin/fleet',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const pageSize = utils.clampInt(req.query.page_size, 1, 100, 25);
            const requestedPage = utils.clampInt(req.query.page, 1, 1e9, 1);
            const q = utils.sanitizeString(req.query.q, 100) || '';
            const allowedFilters = ['all', 'online', 'offline', 'blocked'];
            const filter = allowedFilters.includes(req.query.filter) ? req.query.filter : 'all';

            // Online cutoff is computed in JS as an ISO 8601 string because
            // last_seen_at is stored via new Date().toISOString(). Comparing it
            // against SQLite's datetime('now') would mismatch formats and
            // silently misclassify every device — so we never do that.
            const windowSeconds = utils.getHeartbeatWindowSeconds();
            const threshold = new Date(Date.now() - windowSeconds * 1000).toISOString();

            // Build the filtered WHERE for the page + its COUNT.
            const conditions = [];
            const whereParams = [];
            if (filter === 'online') {
                conditions.push('d.last_seen_at >= ?');
                whereParams.push(threshold);
            } else if (filter === 'offline') {
                conditions.push('(d.last_seen_at IS NULL OR d.last_seen_at < ?)');
                whereParams.push(threshold);
            } else if (filter === 'blocked') {
                conditions.push("u.status NOT IN ('active', 'trial')");
            }
            if (q) {
                const like = likePattern(q);
                conditions.push(
                    "(d.device_uid LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\' OR d.tunnel_host LIKE ? ESCAPE '\\')"
                );
                whereParams.push(like, like, like);
            }
            const whereSql = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

            const totalRow = await dbGet(
                `
                SELECT COUNT(*) AS total
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                ${whereSql}
            `,
                whereParams
            );
            const total = Number(totalRow ? totalRow.total : 0);
            const totalPages = Math.max(1, Math.ceil(total / pageSize));
            const page = Math.min(requestedPage, totalPages);
            const offset = (page - 1) * pageSize;

            // The denormalized log_count / last_event_* columns (migration 006,
            // kept current by device.insertDeviceLog) let this read the latest
            // event straight off the devices row — no per-device subqueries —
            // so LIMIT/OFFSET paging stays cheap. idx_devices_fleet_sort
            // (migration 007) backs the ORDER BY.
            const rows = await dbAll(
                `
                SELECT
                    d.*,
                    u.id AS user_id,
                    u.email AS user_email,
                    u.status AS user_status,
                    u.subdomain AS user_subdomain
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                ${whereSql}
                ORDER BY d.last_seen_at DESC, d.updated_at DESC, d.created_at DESC
                LIMIT ? OFFSET ?
            `,
                [...whereParams, pageSize, offset]
            );

            const devices = rows.map((row) => {
                const data = device.serializeDevice(row);
                return {
                    ...data,
                    log_count: Number(row.log_count || 0),
                    last_event: row.last_event_at
                        ? {
                              level: row.last_event_level,
                              event_type: row.last_event_type,
                              message: row.last_event_message,
                              created_at: row.last_event_at
                          }
                        : null
                };
            });

            // Whole-fleet stats for the overview cards — independent of the
            // search term AND the active filter, so the cards always show the
            // full fleet's online/offline/blocked split.
            const statsRow =
                (await dbGet(
                    `
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN d.last_seen_at >= ? THEN 1 ELSE 0 END) AS online,
                        SUM(CASE WHEN u.status NOT IN ('active', 'trial') THEN 1 ELSE 0 END) AS blocked
                    FROM devices d
                    INNER JOIN users u ON u.id = d.user_id
                `,
                    [threshold]
                )) || {};
            const statsTotal = Number(statsRow.total || 0);
            const statsOnline = Number(statsRow.online || 0);
            const stats = {
                total: statsTotal,
                online: statsOnline,
                offline: statsTotal - statsOnline,
                blocked: Number(statsRow.blocked || 0)
            };

            return res.status(200).json({
                stats,
                page: { page, page_size: pageSize, total, total_pages: totalPages },
                heartbeat_window_seconds: windowSeconds,
                devices
            });
        })
    );

    router.get(
        '/api/admin/fleet/:id/logs',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const deviceId = utils.parsePositiveInt(req.params.id);
            const requestedLimit = Number(req.query.limit);
            const limit = Number.isFinite(requestedLimit)
                ? Math.max(10, Math.min(200, Math.round(requestedLimit)))
                : 60;

            if (!deviceId) {
                return res.status(400).json({ error: 'Invalid device id' });
            }

            const deviceRow = await device.getDeviceWithOwnerById(deviceId);
            if (!deviceRow) {
                return res.status(404).json({ error: 'Device not found' });
            }

            const deviceLogs = await dbAll(
                `
                SELECT id, level, event_type, message, payload, created_at
                FROM device_logs
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
            `,
                [deviceId, limit]
            );

            const adminLogs = await dbAll(
                `
                SELECT id, admin_email, action, details, created_at
                FROM admin_access_logs
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
            `,
                [deviceId, Math.max(10, Math.min(100, Math.round(limit / 2)))]
            );

            return res.status(200).json({
                device: device.serializeDevice(deviceRow),
                logs: deviceLogs.map((entry) => ({
                    id: entry.id,
                    level: entry.level,
                    event_type: entry.event_type,
                    message: entry.message,
                    payload: utils.parseJsonSafe(entry.payload, entry.payload),
                    created_at: entry.created_at
                })),
                admin_actions: adminLogs.map((entry) => ({
                    id: entry.id,
                    admin_email: entry.admin_email,
                    action: entry.action,
                    details: utils.parseJsonSafe(entry.details, entry.details),
                    created_at: entry.created_at
                }))
            });
        })
    );

    router.post(
        '/api/admin/fleet/:id/connect',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const deviceId = utils.parsePositiveInt(req.params.id);

            if (!deviceId) {
                return res.status(400).json({ error: 'Invalid device id' });
            }

            const deviceRow = await device.getDeviceWithOwnerById(deviceId);
            if (!deviceRow) {
                return res.status(404).json({ error: 'Device not found' });
            }

            if (!utils.isAccessEnabled(deviceRow.user_status)) {
                return res.status(403).json({ error: 'Owner account is not active for remote access' });
            }

            const command = device.buildAdminConnectCommand(deviceRow);

            if (!command) {
                return res.status(409).json({ error: 'Device tunnel is not ready. Wait for next heartbeat.' });
            }

            const reason = utils.sanitizeString(req.body?.reason, 200);

            await device.insertAdminAccessLog(deviceId, req.admin.email, 'connect_command_issued', {
                reason: reason || null,
                device_uid: deviceRow.device_uid,
                tunnel_host: deviceRow.tunnel_host,
                tunnel_port: deviceRow.tunnel_port,
                ssh_route: utils.getAdminSshRoute(),
                remote_user: 'root'
            });

            await device.insertDeviceLog(
                deviceId,
                'info',
                'admin.connect',
                `Admin ${req.admin.email} generated an SSH connect command`,
                {
                    reason: reason || null,
                    ssh_route: utils.getAdminSshRoute()
                }
            );

            return res.status(200).json({
                device: device.serializeDevice(deviceRow),
                connect: {
                    command
                }
            });
        })
    );

    return router;
};
