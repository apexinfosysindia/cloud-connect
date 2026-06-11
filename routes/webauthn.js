const express = require('express');
const bcrypt = require('bcryptjs');

/**
 * Passkey enrollment + management routes for both portals.
 *
 * Login step-up (the 2FA gate at sign-in) lives in routes/auth.js and
 * routes/admin.js — this file only handles the authenticated management of
 * passkeys: registering a new one, listing, and removing (password-confirmed).
 *
 * Customer routes are gated by auth.requirePortalUser (req.portalUser); admin
 * routes by auth.requireAdmin + auth.requireAdminSudo (fresh re-auth required
 * before any admin passkey mutation). Each builds a `principal` that
 * lib/webauthn.js uses to scope credentials + challenges.
 */
module.exports = function ({ webauthn, auth, utils }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    function customerPrincipal(req) {
        return {
            kind: 'customer',
            subject: req.portalUser.email,
            userId: req.portalUser.id,
            displayName: req.portalUser.email
        };
    }

    function adminPrincipal() {
        const email = process.env.ADMIN_EMAIL;
        return { kind: 'admin', subject: email, adminEmail: email, displayName: email };
    }

    // ── Customer (Oasis) ───────────────────────────────────────────────────

    router.post(
        '/api/account/passkeys/register/options',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const options = await webauthn.beginRegistration(customerPrincipal(req));
            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({ options });
        })
    );

    router.post(
        '/api/account/passkeys/register/verify',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const principal = customerPrincipal(req);
            const result = await webauthn.finishRegistration(principal, req.body?.response);
            if (!result.verified) {
                console.error('[webauthn] customer registration verify failed:', result.error);
                return res.status(400).json({ error: result.error || 'Could not verify passkey. Please try again.' });
            }
            await webauthn.insertCredential(principal, result.credential, req.body?.nickname);
            await webauthn.setCustomerPasskeyEnabled(req.portalUser.id, true);
            res.status(201).json({ message: 'Passkey registered' });
        })
    );

    router.get(
        '/api/account/passkeys',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const creds = await webauthn.listCredentials(customerPrincipal(req));
            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({ passkeys: creds.map((c) => webauthn.serializeCredential(c)) });
        })
    );

    router.post(
        '/api/account/passkeys/delete',
        auth.requirePortalUser,
        asyncHandler(async (req, res) => {
            const { password, id } = req.body || {};
            const credentialRowId = utils.parsePositiveInt(id);
            if (!credentialRowId) {
                return res.status(400).json({ error: 'A passkey id is required' });
            }
            if (!password) {
                return res.status(400).json({ error: 'Your password is required to remove a passkey' });
            }
            const passwordOk = await bcrypt.compare(password, req.portalUser.password);
            if (!passwordOk) {
                return res.status(401).json({ error: 'Incorrect password' });
            }

            const principal = customerPrincipal(req);
            const removed = await webauthn.deleteCredential(principal, credentialRowId);
            if (!removed) {
                return res.status(404).json({ error: 'Passkey not found' });
            }
            const remaining = await webauthn.countCredentials(principal);
            if (remaining === 0) {
                await webauthn.setCustomerPasskeyEnabled(req.portalUser.id, false);
            }
            res.status(200).json({ message: 'Passkey removed', remaining });
        })
    );

    // ── Admin (Vista) ────────────────────────────────────────────────────────
    // Every admin passkey route additionally requires a fresh sudo grant
    // (requireAdminSudo), so a stolen 8h session token alone cannot view or
    // mutate passkeys — the admin must have re-proven password + passkey on the
    // security page within the last few minutes.

    router.post(
        '/api/admin/passkeys/register/options',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const options = await webauthn.beginRegistration(adminPrincipal());
            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({ options });
        })
    );

    router.post(
        '/api/admin/passkeys/register/verify',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const principal = adminPrincipal();
            const result = await webauthn.finishRegistration(principal, req.body?.response);
            if (!result.verified) {
                console.error('[webauthn] admin registration verify failed:', result.error);
                return res.status(400).json({ error: result.error || 'Could not verify passkey. Please try again.' });
            }
            await webauthn.insertCredential(principal, result.credential, req.body?.nickname);
            res.status(201).json({ message: 'Passkey registered' });
        })
    );

    router.get(
        '/api/admin/passkeys',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const creds = await webauthn.listCredentials(adminPrincipal());
            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({
                passkeys: creds.map((c) => webauthn.serializeCredential(c)),
                break_glass: webauthn.isAdminPasskeyBreakGlass()
            });
        })
    );

    router.post(
        '/api/admin/passkeys/delete',
        auth.requireAdmin,
        auth.requireAdminSudo,
        asyncHandler(async (req, res) => {
            const { password, id } = req.body || {};
            const credentialRowId = utils.parsePositiveInt(id);
            if (!credentialRowId) {
                return res.status(400).json({ error: 'A passkey id is required' });
            }
            if (!password) {
                return res.status(400).json({ error: 'Your admin password is required to remove a passkey' });
            }
            const passwordOk = await auth.verifyAdminPassword(password);
            if (!passwordOk) {
                return res.status(401).json({ error: 'Incorrect password' });
            }

            const removed = await webauthn.deleteCredential(adminPrincipal(), credentialRowId);
            if (!removed) {
                return res.status(404).json({ error: 'Passkey not found' });
            }
            const remaining = await webauthn.countCredentials(adminPrincipal());
            res.status(200).json({ message: 'Passkey removed', remaining });
        })
    );

    return router;
};
