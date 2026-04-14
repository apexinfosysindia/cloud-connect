const express = require('express');

module.exports = function ({ dbGet, dbRun, config, utils, auth, device }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/internal/devices/register',
        asyncHandler(async (req, res) => {
            const accessToken = utils.sanitizeString(req.body?.access_token, 180);
            const deviceUid = utils.sanitizeDeviceUid(req.body?.device_uid);

            if (!accessToken || !deviceUid) {
                return res.status(400).json({ error: 'access_token and device_uid are required' });
            }

            const user = await dbGet(`SELECT * FROM users WHERE access_token = ?`, [accessToken]);

            if (!user) {
                return res.status(404).json({ error: 'No account found for this access token' });
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).json({ error: 'Account is not active for remote access' });
            }

            const nowIso = new Date().toISOString();
            const deviceToken = utils.generateDeviceAuthToken();
            const deviceTokenHash = utils.hashSecret(deviceToken);
            const incomingDeviceName = utils.sanitizeDeviceName(req.body?.device_name);
            const hostname = utils.sanitizeString(req.body?.hostname, 120);
            const localIps = utils.normalizeLocalIps(req.body?.local_ips);
            const sshPort = utils.sanitizePort(req.body?.ssh_port) || 22;
            const remoteUser = 'root';
            const addonVersion = utils.sanitizeString(req.body?.addon_version, 64);
            const agentState = utils.sanitizeString(req.body?.agent_state, 64);
            const defaultDeviceName = incomingDeviceName || hostname || deviceUid;

            const existing = await dbGet(
                `SELECT id, device_name, admin_name_override, tunnel_host, tunnel_port FROM devices WHERE user_id = ? AND device_uid = ?`,
                [user.id, deviceUid]
            );

            let deviceId;
            let assignedTunnelHost = null;
            let assignedTunnelPort = null;

            if (existing) {
                const preservedName = existing.admin_name_override
                    ? utils.sanitizeDeviceName(existing.device_name)
                    : null;
                const nextDeviceName =
                    preservedName ||
                    incomingDeviceName ||
                    utils.sanitizeDeviceName(existing.device_name) ||
                    defaultDeviceName;
                assignedTunnelHost = utils.sanitizeString(existing.tunnel_host, 255) || config.DEVICE_TUNNEL_HOST;
                assignedTunnelPort = utils.sanitizePort(existing.tunnel_port);
                if (!assignedTunnelPort || !utils.isDeviceTunnelPortInRange(assignedTunnelPort)) {
                    assignedTunnelPort = await device.allocateDeviceTunnelPort(existing.id);
                }

                await dbRun(
                    `
                    UPDATE devices
                    SET device_name = ?,
                        hostname = ?,
                        local_ips = ?,
                        ssh_port = ?,
                        remote_user = ?,
                        tunnel_host = ?,
                        tunnel_port = ?,
                        addon_version = ?,
                        agent_state = ?,
                        device_token_hash = ?,
                        last_seen_at = ?,
                        updated_at = ?
                    WHERE id = ?
                `,
                    [
                        nextDeviceName,
                        hostname,
                        localIps,
                        sshPort,
                        remoteUser,
                        assignedTunnelHost,
                        assignedTunnelPort,
                        addonVersion,
                        agentState,
                        deviceTokenHash,
                        nowIso,
                        nowIso,
                        existing.id
                    ]
                );
                deviceId = existing.id;
            } else {
                assignedTunnelHost = config.DEVICE_TUNNEL_HOST;
                assignedTunnelPort = await device.allocateDeviceTunnelPort();

                const insertResult = await dbRun(
                    `
                    INSERT INTO devices (
                        user_id,
                        device_uid,
                        device_name,
                        hostname,
                        local_ips,
                        ssh_port,
                        remote_user,
                        tunnel_host,
                        tunnel_port,
                        addon_version,
                        agent_state,
                        device_token_hash,
                        last_seen_at,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                    [
                        user.id,
                        deviceUid,
                        defaultDeviceName,
                        hostname,
                        localIps,
                        sshPort,
                        remoteUser,
                        assignedTunnelHost,
                        assignedTunnelPort,
                        addonVersion,
                        agentState,
                        deviceTokenHash,
                        nowIso,
                        nowIso,
                        nowIso
                    ]
                );
                deviceId = insertResult.lastID;
            }

            await device.insertDeviceLog(
                deviceId,
                'info',
                existing ? 'device.re_register' : 'device.register',
                existing ? 'Device registration refreshed' : 'Device registered',
                {
                    device_uid: deviceUid,
                    hostname,
                    addon_version: addonVersion,
                    tunnel_host: assignedTunnelHost,
                    tunnel_port: assignedTunnelPort
                }
            );

            const deviceRow = await device.getDeviceWithOwnerById(deviceId);

            return res.status(existing ? 200 : 201).json({
                message: existing ? 'Device registration updated' : 'Device registered',
                device_token: deviceToken,
                heartbeat_interval_seconds: utils.getHeartbeatIntervalSeconds(),
                data: device.serializeDevice(deviceRow)
            });
        })
    );

    router.post(
        '/api/internal/devices/heartbeat',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const nowIso = new Date().toISOString();
            const body = req.body || {};
            const hasOwn = Object.prototype.hasOwnProperty;
            const current = req.device;
            const currentAdminOverride = Number(current.admin_name_override || 0) === 1;

            const incomingDeviceName = hasOwn.call(body, 'device_name')
                ? utils.sanitizeDeviceName(body.device_name)
                : utils.sanitizeDeviceName(current.device_name);
            const deviceName = currentAdminOverride
                ? utils.sanitizeDeviceName(current.device_name)
                : incomingDeviceName;
            const hostname = hasOwn.call(body, 'hostname')
                ? utils.sanitizeString(body.hostname, 120)
                : current.hostname;
            const localIps = hasOwn.call(body, 'local_ips')
                ? utils.normalizeLocalIps(body.local_ips)
                : current.local_ips;

            const nextSshPort = hasOwn.call(body, 'ssh_port')
                ? utils.sanitizePort(body.ssh_port) || current.ssh_port || 22
                : current.ssh_port || 22;

            const nextRemoteUser = 'root';

            const tunnelHost = utils.sanitizeString(current.tunnel_host, 255) || config.DEVICE_TUNNEL_HOST;
            let nextTunnelPort = utils.sanitizePort(current.tunnel_port);
            if (!nextTunnelPort || !utils.isDeviceTunnelPortInRange(nextTunnelPort)) {
                nextTunnelPort = await device.allocateDeviceTunnelPort(current.id);
            }

            const addonVersion = hasOwn.call(body, 'addon_version')
                ? utils.sanitizeString(body.addon_version, 64)
                : current.addon_version;

            const agentState = hasOwn.call(body, 'agent_state')
                ? utils.sanitizeString(body.agent_state, 64)
                : current.agent_state;

            await dbRun(
                `
                UPDATE devices
                SET device_name = ?,
                    hostname = ?,
                    local_ips = ?,
                    ssh_port = ?,
                    remote_user = ?,
                    tunnel_host = ?,
                    tunnel_port = ?,
                    addon_version = ?,
                    agent_state = ?,
                    last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
            `,
                [
                    deviceName,
                    hostname,
                    localIps,
                    nextSshPort,
                    nextRemoteUser,
                    tunnelHost,
                    nextTunnelPort,
                    addonVersion,
                    agentState,
                    nowIso,
                    nowIso,
                    current.id
                ]
            );

            if (agentState && agentState !== current.agent_state) {
                await device.insertDeviceLog(
                    current.id,
                    'info',
                    'device.state',
                    `Agent state changed to ${agentState}`,
                    {
                        previous_state: current.agent_state,
                        current_state: agentState
                    }
                );
            }

            const updated = await device.getDeviceWithOwnerById(current.id);

            return res.status(200).json({
                message: 'Heartbeat accepted',
                heartbeat_interval_seconds: utils.getHeartbeatIntervalSeconds(),
                data: device.serializeDevice(updated)
            });
        })
    );

    router.post(
        '/api/internal/devices/log',
        auth.requireDeviceAuth,
        asyncHandler(async (req, res) => {
            const level = utils.sanitizeString(req.body?.level, 12)?.toLowerCase() || 'info';
            const eventType = utils.sanitizeEventType(req.body?.event_type);
            const message = utils.sanitizeString(req.body?.message, 400);
            const payload = req.body?.payload || null;

            if (!eventType || !message) {
                return res.status(400).json({ error: 'event_type and message are required' });
            }

            await device.insertDeviceLog(req.device.id, level, eventType, message, payload);

            const nowIso = new Date().toISOString();
            await dbRun(
                `
                UPDATE devices
                SET last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
            `,
                [nowIso, nowIso, req.device.id]
            );

            return res.status(200).json({ message: 'Log stored' });
        })
    );

    return router;
};
