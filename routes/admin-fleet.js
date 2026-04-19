const express = require('express');

module.exports = function ({ dbRun, dbAll, utils, auth, device }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.get(
        '/api/admin/fleet',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const rows = await dbAll(
                `
                SELECT
                    d.*,
                    u.id AS user_id,
                    u.email AS user_email,
                    u.status AS user_status,
                    u.subdomain AS user_subdomain,
                    (
                        SELECT COUNT(*)
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                    ) AS log_count,
                    (
                        SELECT dl.level
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_level,
                    (
                        SELECT dl.event_type
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_type,
                    (
                        SELECT dl.message
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_message,
                    (
                        SELECT dl.created_at
                        FROM device_logs dl
                        WHERE dl.device_id = d.id
                        ORDER BY dl.id DESC
                        LIMIT 1
                    ) AS last_event_at
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                ORDER BY d.last_seen_at DESC, d.updated_at DESC, d.created_at DESC
            `
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

            const stats = {
                total: devices.length,
                online: devices.filter((d) => d.online).length,
                offline: devices.filter((d) => !d.online).length,
                connect_ready: devices.filter((d) => d.connect_ready).length,
                blocked: devices.filter((d) => !d.account_enabled).length
            };

            return res.status(200).json({
                stats,
                heartbeat_window_seconds: utils.getHeartbeatWindowSeconds(),
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
        '/api/admin/fleet/:id/name',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const deviceId = utils.parsePositiveInt(req.params.id);
            if (!deviceId) {
                return res.status(400).json({ error: 'Invalid device id' });
            }

            const rawName = utils.sanitizeString(req.body?.device_name, 120);
            if (!rawName) {
                return res.status(400).json({ error: 'device_name is required' });
            }

            const deviceName = utils.sanitizeDeviceName(rawName);
            if (!deviceName) {
                return res.status(400).json({ error: 'device_name is invalid' });
            }

            const deviceRow = await device.getDeviceWithOwnerById(deviceId);
            if (!deviceRow) {
                return res.status(404).json({ error: 'Device not found' });
            }

            const nowIso = new Date().toISOString();
            await dbRun(
                `
                UPDATE devices
                SET device_name = ?,
                    admin_name_override = 1,
                    updated_at = ?
                WHERE id = ?
            `,
                [deviceName, nowIso, deviceId]
            );

            await device.insertAdminAccessLog(deviceId, req.admin.email, 'device_rename', {
                previous_name: deviceRow.device_name || null,
                next_name: deviceName,
                device_uid: deviceRow.device_uid
            });

            await device.insertDeviceLog(
                deviceId,
                'info',
                'admin.rename',
                `Admin ${req.admin.email} renamed device to ${deviceName}`,
                {
                    previous_name: deviceRow.device_name || null,
                    next_name: deviceName
                }
            );

            const updated = await device.getDeviceWithOwnerById(deviceId);
            return res.status(200).json({
                message: 'Device name updated',
                device: device.serializeDevice(updated)
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
