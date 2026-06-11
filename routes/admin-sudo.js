const express = require('express');

/**
 * Admin "sudo mode" re-authentication for the fortress security page.
 *
 * The 8h admin session token alone must NOT be enough to add/remove a passkey.
 * Before any sensitive control, the admin re-proves identity here:
 *   1. POST /api/admin/sudo/options { password }
 *        - verify the admin password
 *        - if no passkey enrolled (or break-glass): issue the sudo grant now
 *        - else: return 202 + a WebAuthn assertion challenge
 *   2. POST /api/admin/sudo/verify { assertion }
 *        - verify the assertion, then issue the sudo grant
 *
 * The grant is a short-lived (5 min) scoped token bound to the exact 8h session
 * that requested it (see lib/auth.js createScopedAdminToken / requireAdminSudo).
 * Both endpoints sit behind requireAdmin, so a valid 8h session is the floor.
 */
module.exports = function ({ auth, webauthn, utils }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    const SUDO_TTL_MS = 5 * 60 * 1000;

    function adminPrincipal() {
        const email = process.env.ADMIN_EMAIL;
        return { kind: 'admin', subject: email, adminEmail: email, displayName: email };
    }

    function baseBearer(req) {
        const authHeader = req.get('authorization') || '';
        return authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    }

    function issueGrant(req, res) {
        const sudoToken = auth.createScopedAdminToken(process.env.ADMIN_EMAIL, {
            scope: 'sudo',
            ttlMs: SUDO_TTL_MS,
            bind: auth.computeSudoBind(baseBearer(req))
        });
        res.setHeader('Cache-Control', 'no-store');
        return res.status(200).json({ sudo_token: sudoToken, expires_in: Math.floor(SUDO_TTL_MS / 1000) });
    }

    router.post(
        '/api/admin/sudo/options',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const password = req.body?.password;
            if (!password) {
                return res.status(400).json({ error: 'Admin password is required' });
            }

            const passwordOk = await auth.verifyAdminPassword(password);
            if (!passwordOk) {
                return res.status(401).json({ error: 'Incorrect admin password' });
            }

            // Password proven. If a passkey is enrolled and break-glass is off,
            // require the assertion too; otherwise grant sudo on password alone.
            const principal = adminPrincipal();
            if (!webauthn.isAdminPasskeyBreakGlass()) {
                const options = await webauthn.beginAuthentication(principal);
                if (options) {
                    res.setHeader('Cache-Control', 'no-store');
                    return res.status(202).json({ mfa_required: true, mfa_method: 'passkey', options });
                }
            }

            return issueGrant(req, res);
        })
    );

    router.post(
        '/api/admin/sudo/verify',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const assertion = req.body?.assertion || req.body?.response;
            if (!assertion) {
                return res.status(400).json({ error: 'A passkey assertion is required' });
            }

            const result = await webauthn.finishAuthentication(adminPrincipal(), assertion);
            if (!result.verified) {
                console.error('[webauthn] admin sudo passkey verify failed:', result.error);
                return res.status(401).json({ error: 'Passkey verification failed. Please try again.' });
            }

            return issueGrant(req, res);
        })
    );

    return router;
};
