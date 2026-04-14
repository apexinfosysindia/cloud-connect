module.exports = function ({ dbGet, dbRun, dbAll, config, utils }) {
    async function allocateDeviceTunnelPort(excludedDeviceId = null) {
        const { min, max } = utils.getDeviceTunnelPortRange();
        const rows = excludedDeviceId
            ? await dbAll(
                  `
                    SELECT tunnel_port
                    FROM devices
                    WHERE tunnel_port IS NOT NULL
                      AND tunnel_port BETWEEN ? AND ?
                      AND id != ?
                    ORDER BY tunnel_port ASC
                `,
                  [min, max, excludedDeviceId]
              )
            : await dbAll(
                  `
                    SELECT tunnel_port
                    FROM devices
                    WHERE tunnel_port IS NOT NULL
                      AND tunnel_port BETWEEN ? AND ?
                    ORDER BY tunnel_port ASC
                `,
                  [min, max]
              );

        const usedPorts = new Set(
            (rows || [])
                .map((row) => Number(row.tunnel_port))
                .filter((port) => Number.isInteger(port) && port >= min && port <= max)
        );

        for (let port = min; port <= max; port += 1) {
            if (!usedPorts.has(port)) {
                return port;
            }
        }

        return null;
    }

    function serializeDevice(row) {
        const ownerDomain = row.user_subdomain ? `${row.user_subdomain}.${config.CLOUD_BASE_DOMAIN}` : null;
        const online = utils.isDeviceOnline(row.last_seen_at);
        const accountEnabled = utils.isAccessEnabled(row.user_status);
        const connectReady = accountEnabled && utils.isDeviceTunnelPortInRange(utils.sanitizePort(row.tunnel_port));
        const sshRoute = utils.getAdminSshRoute();

        return {
            id: row.id,
            owner: {
                user_id: row.user_id,
                email: row.user_email,
                status: row.user_status,
                domain: ownerDomain
            },
            device_uid: row.device_uid,
            device_name: row.device_name,
            admin_name_override: Boolean(row.admin_name_override),
            hostname: row.hostname,
            local_ips: row.local_ips ? row.local_ips.split(',').filter(Boolean) : [],
            ssh_port: row.ssh_port || 22,
            remote_user: row.remote_user || 'root',
            tunnel_host: row.tunnel_host,
            tunnel_port: row.tunnel_port,
            ssh_route: sshRoute,
            addon_version: row.addon_version,
            agent_state: row.agent_state,
            online,
            connect_ready: connectReady,
            account_enabled: accountEnabled,
            last_seen_at: row.last_seen_at,
            created_at: row.created_at,
            updated_at: row.updated_at
        };
    }

    async function insertDeviceLog(deviceId, level, eventType, message, payload = null) {
        const normalizedLevel = ['info', 'warn', 'error'].includes(level) ? level : 'info';
        const normalizedEventType = utils.sanitizeEventType(eventType) || 'event';
        const normalizedMessage = utils.sanitizeString(message, 400) || 'Device event';
        const payloadText = payload ? JSON.stringify(payload).slice(0, 2000) : null;

        await dbRun(
            `
                INSERT INTO device_logs (device_id, level, event_type, message, payload)
                VALUES (?, ?, ?, ?, ?)
            `,
            [deviceId, normalizedLevel, normalizedEventType, normalizedMessage, payloadText]
        );

        await dbRun(
            `
                DELETE FROM device_logs
                WHERE device_id = ?
                  AND id NOT IN (
                    SELECT id FROM device_logs WHERE device_id = ? ORDER BY id DESC LIMIT 250
                  )
            `,
            [deviceId, deviceId]
        );
    }

    async function insertAdminAccessLog(deviceId, adminEmail, action, details = null) {
        await dbRun(
            `
                INSERT INTO admin_access_logs (device_id, admin_email, action, details)
                VALUES (?, ?, ?, ?)
            `,
            [deviceId || null, adminEmail, action, details ? JSON.stringify(details).slice(0, 2000) : null]
        );
    }

    async function findDeviceByToken(deviceToken) {
        if (!deviceToken) {
            return null;
        }

        const tokenHash = utils.hashSecret(deviceToken);
        return await dbGet(
            `
                SELECT
                    d.*,
                    u.id AS user_id,
                    u.email AS user_email,
                    u.status AS user_status,
                    u.subdomain AS user_subdomain
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                WHERE d.device_token_hash = ?
            `,
            [tokenHash]
        );
    }

    async function createUniqueAccessToken() {
        while (true) {
            const candidate = utils.generateToken();
            const existing = await dbGet(`SELECT id FROM users WHERE access_token = ?`, [candidate]);
            if (!existing) {
                return candidate;
            }
        }
    }

    async function getDeviceWithOwnerById(deviceId) {
        return await dbGet(
            `
                SELECT
                    d.*,
                    u.id AS user_id,
                    u.email AS user_email,
                    u.status AS user_status,
                    u.subdomain AS user_subdomain
                FROM devices d
                INNER JOIN users u ON u.id = d.user_id
                WHERE d.id = ?
            `,
            [deviceId]
        );
    }

    function buildAdminConnectCommand(device) {
        const tunnelPort = utils.sanitizePort(device.tunnel_port);
        const sshRoute = utils.getAdminSshRoute();

        if (!tunnelPort || !utils.isDeviceTunnelPortInRange(tunnelPort)) {
            return null;
        }

        const jumpHostArg =
            sshRoute.jump_port === 22
                ? `${sshRoute.jump_user}@${sshRoute.jump_host}`
                : `${sshRoute.jump_user}@${sshRoute.jump_host} -p ${sshRoute.jump_port}`;

        return `ssh -o "ProxyCommand=ssh -i ~/.ssh/jump_key -W %h:%p ${jumpHostArg}" -i ~/.ssh/device_key -p ${tunnelPort} ${sshRoute.target_user}@${sshRoute.target_host}`;
    }

    return {
        allocateDeviceTunnelPort,
        serializeDevice,
        insertDeviceLog,
        insertAdminAccessLog,
        findDeviceByToken,
        createUniqueAccessToken,
        getDeviceWithOwnerById,
        buildAdminConnectCommand
    };
};
