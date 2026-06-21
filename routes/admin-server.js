const express = require('express');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { execFile: nodeExecFile } = require('child_process');

/**
 * Vista admin — Server Health & Controls.
 *
 * READ endpoints (requireAdmin):
 *   GET  /api/admin/server/health      → process + os + pm2 + disk metrics
 *   GET  /api/admin/server/logs        → tail of the PM2 app log files
 *   GET  /api/admin/server/app-events  → in-memory app-event ring buffer
 *
 * CONTROL endpoints (requireAdmin + requireAdminSudo + audit log):
 *   POST /api/admin/server/restart-app → pm2 restart apex-portal
 *   POST /api/admin/server/reboot      → sudo -n /sbin/reboot
 *
 * SECURITY: the app process runs as a user with NOPASSWD:ALL on the box, so these
 * controls are effectively root. Every control requires a FRESH 5-minute sudo grant
 * (requireAdminSudo) on top of the 8h admin session, and writes an admin_access_logs
 * row. Commands are LITERALS run via execFile with fixed argument arrays — no user
 * input ever reaches a shell, so there is no command-injection surface.
 *
 * `execFile` is injectable (deps.execFile) so tests can stub it and assert the command
 * WITHOUT executing anything.
 */
module.exports = function ({ utils, auth, device, execFile = nodeExecFile }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    const PM2_PROCESS = 'apex-portal';
    const PM2_LOG_DIR = path.join(os.homedir(), '.pm2', 'logs');
    const PM2_LOGS = {
        pm2_out: path.join(PM2_LOG_DIR, 'apex-portal-out.log'),
        pm2_err: path.join(PM2_LOG_DIR, 'apex-portal-error.log')
    };
    const LOG_TAIL_MAX_BYTES = 64 * 1024;
    const LOG_TAIL_MAX_LINES = 500;

    // Promisified execFile with a hard timeout; never throws (returns {error}).
    function run(cmd, args, timeoutMs = 8000) {
        return new Promise((resolve) => {
            try {
                execFile(cmd, args, { timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
                    resolve({ error: error || null, stdout: stdout || '', stderr: stderr || '' });
                });
            } catch (e) {
                resolve({ error: e, stdout: '', stderr: '' });
            }
        });
    }

    // Read the last `lines` lines of a file by reading only the trailing chunk.
    function tailFile(filePath, lines) {
        try {
            const stat = fs.statSync(filePath);
            const start = Math.max(0, stat.size - LOG_TAIL_MAX_BYTES);
            const fd = fs.openSync(filePath, 'r');
            try {
                const len = stat.size - start;
                const buf = Buffer.alloc(len);
                fs.readSync(fd, buf, 0, len, start);
                const text = buf.toString('utf8');
                const all = text.split('\n');
                // drop a partial first line if we started mid-file
                if (start > 0 && all.length) all.shift();
                return all.filter((l) => l.length > 0).slice(-lines);
            } finally {
                fs.closeSync(fd);
            }
        } catch (_e) {
            return null;
        }
    }

    // Parse `pm2 jlist` JSON for our process; best-effort, null on any failure.
    function parsePm2(jlistStdout) {
        try {
            const arr = JSON.parse(jlistStdout);
            const p = Array.isArray(arr) ? arr.find((x) => x?.name === PM2_PROCESS) : null;
            if (!p) return null;
            const env = p.pm2_env || {};
            return {
                status: env.status || null,
                restarts: typeof env.restart_time === 'number' ? env.restart_time : null,
                unstable_restarts: typeof env.unstable_restarts === 'number' ? env.unstable_restarts : null,
                uptime_ms: env.pm_uptime ? Date.now() - env.pm_uptime : null,
                pid: p.pid || null,
                cpu: p.monit?.cpu ?? null,
                memory_bytes: p.monit?.memory ?? null,
                node_version: env.node_version || null
            };
        } catch (_e) {
            return null;
        }
    }

    // Parse `df -kP /` → { total, used, avail } in KB + percent.
    function parseDf(stdout) {
        try {
            const lines = String(stdout).trim().split('\n');
            const cols = lines[lines.length - 1].trim().split(/\s+/);
            // Filesystem 1024-blocks Used Available Capacity Mounted
            const totalKb = Number(cols[1]);
            const usedKb = Number(cols[2]);
            const availKb = Number(cols[3]);
            const pct = cols[4] || null;
            if (!Number.isFinite(totalKb)) return null;
            return { total_bytes: totalKb * 1024, used_bytes: usedKb * 1024, avail_bytes: availKb * 1024, used_percent: pct };
        } catch (_e) {
            return null;
        }
    }

    function readDeployVersion() {
        try {
            return fs.readFileSync(path.join(process.cwd(), '.deploy-version'), 'utf8').trim().slice(0, 80) || null;
        } catch (_e) {
            return null;
        }
    }

    // ── READ: health ───────────────────────────────────────────────────
    router.get(
        '/api/admin/server/health',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const mem = process.memoryUsage();
            const [pm2res, dfres] = await Promise.all([
                run('pm2', ['jlist']),
                run('df', ['-kP', '/'])
            ]);
            res.status(200).json({
                now: new Date().toISOString(),
                deploy_commit: readDeployVersion(),
                process: {
                    uptime_seconds: Math.round(process.uptime()),
                    pid: process.pid,
                    node_version: process.version,
                    memory: { rss: mem.rss, heap_used: mem.heapUsed, heap_total: mem.heapTotal }
                },
                os: {
                    uptime_seconds: Math.round(os.uptime()),
                    loadavg: os.loadavg(),
                    cpu_count: os.cpus().length,
                    total_mem_bytes: os.totalmem(),
                    free_mem_bytes: os.freemem(),
                    platform: os.platform(),
                    hostname: os.hostname()
                },
                pm2: pm2res.error ? null : parsePm2(pm2res.stdout),
                disk: dfres.error ? null : parseDf(dfres.stdout)
            });
        })
    );

    // ── READ: logs (tail of pm2 files) ─────────────────────────────────
    router.get(
        '/api/admin/server/logs',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const source = req.query?.source === 'pm2_err' ? 'pm2_err' : 'pm2_out';
            let lines = parseInt(req.query?.lines, 10);
            if (!Number.isFinite(lines) || lines <= 0) lines = 200;
            lines = Math.min(lines, LOG_TAIL_MAX_LINES);
            const out = tailFile(PM2_LOGS[source], lines);
            res.status(200).json({
                source,
                available: out !== null,
                lines: out || []
            });
        })
    );

    // ── READ: in-memory app events ─────────────────────────────────────
    router.get(
        '/api/admin/server/app-events',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const { serverState } = require('../lib/server-state');
            const events = (serverState.appEvents || []).slice().reverse(); // newest first
            res.status(200).json({ events });
        })
    );

    // ── CONTROL: restart the app (pm2 restart) ─────────────────────────
    router.post(
        '/api/admin/server/restart-app',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const reason = utils.sanitizeString(req.body?.reason, 300) || null;
            await device.insertAdminAccessLog(null, req.admin.email, 'server_restart_app', { reason });
            // Respond FIRST so the client gets confirmation before our process dies.
            res.status(200).json({ ok: true, restarting: true, process: PM2_PROCESS });
            // pm2 restart hands the work to the PM2 daemon (separate process), so this
            // completes even though our process is killed mid-restart.
            setTimeout(() => {
                run('pm2', ['restart', PM2_PROCESS]).catch(() => {});
            }, 250);
        })
    );

    // ── CONTROL: reboot the server ─────────────────────────────────────
    router.post(
        '/api/admin/server/reboot',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const reason = utils.sanitizeString(req.body?.reason, 300) || null;
            await device.insertAdminAccessLog(null, req.admin.email, 'server_reboot', { reason });
            res.status(200).json({ ok: true, rebooting: true });
            // Detached, after the response flushes. `sudo -n` is non-interactive.
            setTimeout(() => {
                run('sudo', ['-n', '/sbin/reboot'], 5000).catch(() => {});
            }, 500);
        })
    );

    return router;
};
