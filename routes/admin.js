const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function ({ dbAll, dbGet, utils, auth, webauthn, billing }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/admin/login',
        asyncHandler(async (req, res) => {
            const { email, password } = req.body;

            try {
                auth.ensureAdminConfigured();
            } catch (error) {
                return res.status(500).json({ error: error.message });
            }

            if (email !== process.env.ADMIN_EMAIL) {
                return res.status(401).json({ error: 'Invalid admin credentials' });
            }

            const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
            let passwordValid = false;

            if (adminPasswordHash) {
                passwordValid = await bcrypt.compare(password, adminPasswordHash);
            } else if (process.env.ADMIN_PASSWORD) {
                const expectedBuffer = Buffer.from(process.env.ADMIN_PASSWORD);
                const receivedBuffer = Buffer.from(password || '');
                passwordValid =
                    expectedBuffer.length === receivedBuffer.length &&
                    crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
            }

            if (!passwordValid) {
                return res.status(401).json({ error: 'Invalid admin credentials' });
            }

            // Passkey step-up (enforced once an admin passkey is enrolled). The
            // only bypass is the env break-glass flag (set + restart). If a
            // passkey exists and break-glass is off, return 202 and require the
            // assertion via /api/admin/login/passkey/verify before issuing a token.
            if (!webauthn.isAdminPasskeyBreakGlass()) {
                const principal = { kind: 'admin', subject: email, adminEmail: email, displayName: email };
                const options = await webauthn.beginAuthentication(principal);
                if (options) {
                    res.setHeader('Cache-Control', 'no-store');
                    return res.status(202).json({ mfa_required: true, mfa_method: 'passkey', options });
                }
            }

            res.status(200).json({
                message: 'Admin login successful',
                email,
                token: auth.createAdminToken(email)
            });
        })
    );

    // Complete a passkey-gated admin login. Reached only after /api/admin/login
    // verified the password and issued an assertion challenge (202).
    router.post(
        '/api/admin/login/passkey/verify',
        asyncHandler(async (req, res) => {
            try {
                auth.ensureAdminConfigured();
            } catch (error) {
                return res.status(500).json({ error: error.message });
            }

            const email = process.env.ADMIN_EMAIL;
            const assertion = req.body?.assertion || req.body?.response;
            if (!assertion) {
                return res.status(400).json({ error: 'A passkey assertion is required' });
            }

            const principal = { kind: 'admin', subject: email, adminEmail: email, displayName: email };
            const result = await webauthn.finishAuthentication(principal, assertion);
            if (!result.verified) {
                console.error('[webauthn] admin login passkey verify failed:', result.error);
                return res.status(401).json({ error: 'Passkey verification failed. Please sign in again.' });
            }

            res.status(200).json({
                message: 'Admin login successful',
                email,
                token: auth.createAdminToken(email)
            });
        })
    );

    router.get('/api/admin/me', auth.requireAdmin, (req, res) => {
        res.status(200).json({
            email: req.admin.email
        });
    });

    // Security overview for the Vista "Security" view: passkey/2FA posture plus
    // a recent slice of the privileged-action audit trail (admin_access_logs:
    // device SSH access, PM2 restarts, server reboots). requireAdmin only (NO
    // sudo) so it can load automatically with the dashboard — it exposes counts
    // and already-recorded audit rows, never secrets or passkey material.
    const adminPrincipal = () => {
        const email = process.env.ADMIN_EMAIL;
        return { kind: 'admin', subject: email, adminEmail: email, displayName: email };
    };

    router.get(
        '/api/admin/security/overview',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const passkeyCount = await webauthn.countCredentials(adminPrincipal());
            // 2FA is enforced unless the break-glass escape hatch is enabled.
            const twoFactorEnforced = !webauthn.isAdminPasskeyBreakGlass();

            const recentRows = await dbAll(`
                SELECT id, admin_email, action, details, created_at
                FROM admin_access_logs
                ORDER BY id DESC
                LIMIT 12
            `);

            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({
                passkeys: {
                    count: passkeyCount,
                    two_factor_enforced: twoFactorEnforced
                },
                recent: recentRows.map((entry) => ({
                    id: entry.id,
                    admin_email: entry.admin_email,
                    action: entry.action,
                    details: utils.parseJsonSafe(entry.details, entry.details),
                    created_at: entry.created_at
                }))
            });
        })
    );

    router.get(
        '/api/admin/users',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const pageSize = utils.clampInt(req.query.page_size, 1, 100, 25);
            const requestedPage = utils.clampInt(req.query.page, 1, 1e9, 1);
            const q = utils.sanitizeString(req.query.q, 100) || '';

            // Whole-table status tallies for the four overview stat cards. These
            // are independent of the search/page so the cards always reflect the
            // full customer base, not just the rows currently on screen.
            const statsRow =
                (await dbGet(`
                    SELECT
                        SUM(CASE WHEN status = 'payment_pending' THEN 1 ELSE 0 END) AS pending,
                        SUM(CASE WHEN status = 'trial' THEN 1 ELSE 0 END) AS trial,
                        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                        SUM(CASE WHEN status IN ('suspended', 'expired') THEN 1 ELSE 0 END) AS disabled
                    FROM users
                `)) || {};
            const stats = {
                pending: Number(statsRow.pending || 0),
                trial: Number(statsRow.trial || 0),
                active: Number(statsRow.active || 0),
                disabled: Number(statsRow.disabled || 0)
            };

            // Optional server-side search across email / cloud subdomain / status.
            // Escape LIKE wildcards so a literal % or _ in the query is matched
            // as text, not as a wildcard.
            const whereParams = [];
            let whereSql = '';
            if (q) {
                const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
                whereSql = `WHERE (email LIKE ? ESCAPE '\\' OR subdomain LIKE ? ESCAPE '\\' OR status LIKE ? ESCAPE '\\')`;
                whereParams.push(like, like, like);
            }

            const totalRow = await dbGet(`SELECT COUNT(*) AS total FROM users ${whereSql}`, whereParams);
            const total = Number(totalRow ? totalRow.total : 0);
            const totalPages = Math.max(1, Math.ceil(total / pageSize));
            const page = Math.min(requestedPage, totalPages);
            const offset = (page - 1) * pageSize;

            const rows = await dbAll(
                `
                SELECT *
                FROM users
                ${whereSql}
                ORDER BY
                    CASE status
                        WHEN 'payment_pending' THEN 0
                        WHEN 'trial' THEN 1
                        WHEN 'active' THEN 2
                        WHEN 'suspended' THEN 3
                        WHEN 'expired' THEN 4
                        ELSE 5
                    END,
                    created_at DESC
                LIMIT ? OFFSET ?
            `,
                [...whereParams, pageSize, offset]
            );

            res.status(200).json({
                stats,
                page: { page, page_size: pageSize, total, total_pages: totalPages },
                users: rows.map(auth.serializeAdminUser)
            });
        })
    );

    router.post(
        '/api/admin/users/:id/status',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const { id } = req.params;
            const { status, trial_days } = req.body;
            const allowedStatuses = ['active', 'trial', 'suspended'];

            if (!allowedStatuses.includes(status)) {
                return res.status(400).json({ error: 'Invalid status' });
            }

            // Suspend = stop billing AND lock out locally. If the user has a
            // live Razorpay subscription we cancel it first (at cycle end so
            // paid users keep access until period end; trial users get
            // trial-aborted immediately inside cancelSubscription). Best
            // effort: if the Razorpay call fails we still proceed with the
            // local suspend so admins aren't blocked by Razorpay outages,
            // but we report the cancel error back in the response.
            let cancelResult = null;
            let cancelError = null;
            if (status === 'suspended') {
                const existing = await dbGet(`SELECT * FROM users WHERE id = ?`, [Number(id)]);
                if (!existing) {
                    return res.status(404).json({ error: 'User not found' });
                }
                const rzpStatus = String(existing.razorpay_subscription_status || '').toLowerCase();
                const terminal = ['cancelled', 'completed', 'expired', 'halted'].includes(rzpStatus);
                if (existing.razorpay_subscription_id && !terminal) {
                    try {
                        cancelResult = await billing.cancelSubscription(Number(id), { atCycleEnd: true });
                    } catch (error) {
                        console.error(`Admin suspend: Razorpay cancel failed for ${existing.email}:`, error.message);
                        cancelError = error.message || 'Unable to cancel subscription on Razorpay.';
                    }
                }
            }

            const updatedUser = await billing.updateUserStatus(Number(id), status, {
                trialDays: Number(trial_days) || 365
            });

            if (!updatedUser) {
                return res.status(404).json({ error: 'User not found' });
            }

            let message = 'User status updated';
            if (status === 'suspended') {
                if (cancelError) {
                    message = `Account suspended locally, but Razorpay subscription cancel failed: ${cancelError}. Please reconcile manually.`;
                } else if (cancelResult?.trialAbort) {
                    message = `Account suspended and Razorpay trial cancelled. User moved to payment_pending.`;
                } else if (cancelResult?.atCycleEnd) {
                    message = `Account suspended. Razorpay subscription cancelled at cycle end.`;
                } else if (cancelResult?.cancelled) {
                    message = `Account suspended and Razorpay subscription cancelled (no billing cycle had started).`;
                }
            }

            res.status(200).json({
                message,
                user: auth.serializeAdminUser(updatedUser)
            });
        })
    );

    router.delete(
        '/api/admin/users/:id',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const { id } = req.params;

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [Number(id)]);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            const deleted = await billing.deleteUserAccount(Number(id));
            if (!deleted) {
                return res.status(500).json({ error: 'Unable to delete user' });
            }

            res.status(200).json({
                message: `Account ${deleted.email} has been permanently deleted.`
            });
        })
    );

    return router;
};
