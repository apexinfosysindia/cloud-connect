/**
 * Alexa Smart Home OAuth provider routes.
 *
 *   GET  /api/alexa/oauth   — authorize endpoint Amazon redirects to
 *   POST /api/alexa/token   — token endpoint Amazon's Lambda calls
 *
 * ─── What's deliberately MISSING vs. routes/google-home-oauth.js ───────────
 *
 * The Google route has a portal-side CONSENT step (line ~102 in
 * routes/google-home-oauth.js, gated by `req.query?.approved !== '1'`). It
 * redirects the logged-in user to a consent card on /login.html, where they
 * must click "Allow" before the auth code is minted.
 *
 * That step is INTENTIONALLY REMOVED here. Per the v1 Alexa post-mortem,
 * the portal-side consent card was the direct cause of "linking broken in
 * prod": the Alexa app already shows its own consent UI before redirecting
 * to us, so a second consent screen meant users either (a) landed on the
 * dashboard with no obvious "Allow" button, or (b) hit the auto-approve
 * hack in commit 957b7c0 which papered over the UX bug without fixing the
 * underlying linking problem.
 *
 * The new flow:
 *   - User taps "Link Account" in the Alexa app
 *   - Alexa redirects browser → /api/alexa/oauth?client_id=...&redirect_uri=...&state=...
 *   - If portal session present and account active → mint code, 302 back
 *   - If no session → bounce through /login.html carrying the OAuth params,
 *     then auto-issue on successful login
 *
 * This route does NOT validate client_secret at authorize time — Amazon's
 * authorize call does not include it. The /api/alexa/token endpoint below
 * is where client_id + client_secret are both required.
 *
 * ─── Required env vars ─────────────────────────────────────────────────────
 *
 *   ALEXA_OAUTH_CLIENT_ID        — issued by us, registered into Amazon dev console
 *   ALEXA_OAUTH_CLIENT_SECRET    — issued by us, kept secret on Amazon's side
 *   ALEXA_REDIRECT_URI_HOSTS     — allow-list of Amazon-side redirect hosts
 *                                  (defaults to the three regional hosts)
 *
 * The first two are read directly from process.env to keep config.js free of
 * secrets that don't need to be importable by other modules. They're checked
 * at request time and yield a 503 ("alexa_oauth_not_configured") if absent —
 * mirrors the Google side's behavior so operators see a consistent error.
 */

const express = require('express');

function isTrustedAlexaRedirectUri(redirectUri, allowedHosts) {
    if (typeof redirectUri !== 'string' || !redirectUri) return false;
    let parsed;
    try {
        parsed = new URL(redirectUri);
    } catch (_e) {
        return false;
    }
    // Amazon ALWAYS uses https for skill linking. http: is a misconfiguration
    // or attempted spoof — reject either way.
    if (parsed.protocol !== 'https:') return false;
    const host = (parsed.hostname || '').toLowerCase();
    return allowedHosts.includes(host);
}

function buildLoginRedirect(clientId, redirectUri, state) {
    return (
        '/login.html?alexa_oauth=1' +
        `&client_id=${encodeURIComponent(clientId)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${encodeURIComponent(state || '')}`
    );
}

module.exports = function ({ dbGet, dbRun, config, utils, auth, alexaCore }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // ── GET /api/alexa/oauth (authorize) ───────────────────────────────────

    router.get(
        '/api/alexa/oauth',
        asyncHandler(async (req, res) => {
            const clientId = utils.sanitizeString(req.query?.client_id, 255);
            const redirectUri = utils.sanitizeString(req.query?.redirect_uri, 1000);
            const state = utils.sanitizeString(req.query?.state, 1000) || '';

            const clientIdEnv = process.env.ALEXA_OAUTH_CLIENT_ID || '';
            const clientSecretEnv = process.env.ALEXA_OAUTH_CLIENT_SECRET || '';

            // Boot-time config validation — if either secret is missing the
            // skill cannot link at all. Surface 503 (not 500) so operators
            // can distinguish "misconfigured" from "broken".
            if (!clientIdEnv || !clientSecretEnv) {
                return res.status(503).send('Alexa OAuth is not configured');
            }

            if (!clientId || !redirectUri) {
                return res.status(400).send('Missing OAuth parameters');
            }

            // Constant-time-ish comparison would be nicer here, but client_id
            // is not a secret (it's printed in Amazon's dev console). The
            // string equality matches the Google route's pattern.
            if (clientId !== clientIdEnv) {
                return res.status(401).send('Invalid client_id');
            }

            if (!isTrustedAlexaRedirectUri(redirectUri, config.ALEXA_REDIRECT_URI_HOSTS)) {
                return res.status(400).send('Invalid redirect_uri');
            }

            // Resolve the portal session. We accept either:
            //   - the standard portal cookie set on the customer-portal host
            //   - a `portal_session_token` query param, used by the post-login
            //     bounce so a fresh token is honored even before the cookie
            //     round-trips to the OAuth host
            const cookiePortalToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const queryPortalTokenRaw = req.query?.portal_session_token;
            const queryPortalToken =
                typeof queryPortalTokenRaw === 'string' ? queryPortalTokenRaw.trim() : '';
            const portalToken = cookiePortalToken || queryPortalToken;

            const callbackUrl = new URL(redirectUri);

            // Explicit user denial (Alexa app sometimes posts ?error=access_denied
            // back through us if the user backed out of the link page).
            if (req.query?.error || req.query?.deny === '1') {
                callbackUrl.searchParams.set(
                    'error',
                    utils.sanitizeString(req.query.error, 120) || 'access_denied'
                );
                callbackUrl.searchParams.set('state', state);
                return res.redirect(callbackUrl.toString());
            }

            // No session → bounce through portal login carrying the OAuth
            // params. After login, login.html re-issues the same authorize
            // request. We do NOT need Google's `from_cookie=1` ping-pong here
            // because there is no consent step on a different host.
            if (!portalToken) {
                return res.redirect(buildLoginRedirect(clientId, redirectUri, state));
            }

            const session = auth.verifyPortalSessionToken(portalToken);
            if (!session) {
                return res.redirect(buildLoginRedirect(clientId, redirectUri, state));
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                // Session token validates but no matching user — typically a
                // user that was deleted while a session was open. Force re-login.
                return res.redirect(buildLoginRedirect(clientId, redirectUri, state));
            }

            // Defense against stale tokens that survive a password change /
            // global logout: portal-token epoch must still match the user's
            // current epoch. Same pattern as Google route.
            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.redirect(buildLoginRedirect(clientId, redirectUri, state));
            }

            if (!utils.isAccessEnabled(user.status)) {
                // Subscription not active — redirect back to Amazon with
                // access_denied so the link page surfaces a clean error.
                callbackUrl.searchParams.set('error', 'access_denied');
                callbackUrl.searchParams.set('state', state);
                return res.redirect(callbackUrl.toString());
            }

            // Auto-enable Alexa on the user account on first link. This is
            // exactly what the Google flow does for google_home_enabled.
            if (!user.alexa_enabled) {
                await dbRun(`UPDATE users SET alexa_enabled = 1 WHERE id = ?`, [user.id]);
            }

            // ─── DELIBERATELY NO CONSENT STEP HERE ────────────────────────
            // The Google route shows a consent card before this point. We
            // skip it. Alexa's app already showed consent before sending the
            // user to /api/alexa/oauth, so a second prompt is redundant and
            // (per v1 post-mortem) causes "linking broken in prod" symptoms.
            // ──────────────────────────────────────────────────────────────

            const { code } = await alexaCore.issueAlexaAuthCode({
                userId: user.id,
                redirectUri
            });

            callbackUrl.searchParams.set('code', code);
            callbackUrl.searchParams.set('state', state);
            return res.redirect(callbackUrl.toString());
        })
    );

    // ── POST /api/alexa/token (exchange + refresh) ─────────────────────────

    router.post(
        '/api/alexa/token',
        asyncHandler(async (req, res) => {
            const grantType = utils.sanitizeString(req.body?.grant_type, 64);
            const clientId = utils.sanitizeString(req.body?.client_id, 255);
            const clientSecret = utils.sanitizeString(req.body?.client_secret, 255);

            const clientIdEnv = process.env.ALEXA_OAUTH_CLIENT_ID || '';
            const clientSecretEnv = process.env.ALEXA_OAUTH_CLIENT_SECRET || '';

            if (!clientIdEnv || !clientSecretEnv) {
                return res.status(503).json({ error: 'alexa_oauth_not_configured' });
            }

            // Both must match. We answer "invalid_client" rather than
            // distinguishing missing-secret from wrong-secret to avoid
            // leaking which half is wrong.
            if (clientId !== clientIdEnv || clientSecret !== clientSecretEnv) {
                return res.status(401).json({ error: 'invalid_client' });
            }

            // ── authorization_code grant (initial link) ──────────────────
            if (grantType === 'authorization_code') {
                const code = utils.sanitizeString(req.body?.code, 255);
                const redirectUri = utils.sanitizeString(req.body?.redirect_uri, 1000);

                if (!code || !redirectUri) {
                    return res.status(400).json({ error: 'invalid_request' });
                }

                // The redirect_uri presented here MUST equal the one used at
                // authorize time — Alexa enforces this and so do we (see
                // findUserByAlexaAuthCode which scopes the lookup by both).
                const linkedUser = await alexaCore.findUserByAlexaAuthCode(code, redirectUri);
                if (!linkedUser) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }

                if (!linkedUser.alexa_enabled || !utils.isAccessEnabled(linkedUser.status)) {
                    return res.status(403).json({ error: 'access_denied' });
                }

                // Consume the auth code BEFORE issuing tokens so we cannot
                // double-issue if a retry races. Issue happens in the same
                // request so there's no transactional gap worth caring about
                // — if issue fails, the code is gone and the user retries.
                await alexaCore.consumeAlexaAuthCode(linkedUser.oauth_code_id);

                const tokens = await alexaCore.issueAlexaTokensForUser(linkedUser.id);

                // Standard OAuth2 token response shape that Amazon's Lambda
                // expects. token_type "bearer" lowercase per RFC 6749.
                return res.status(200).json({
                    access_token: tokens.accessToken,
                    refresh_token: tokens.refreshToken,
                    token_type: 'bearer',
                    expires_in: tokens.expiresIn
                });
            }

            // ── refresh_token grant ──────────────────────────────────────
            if (grantType === 'refresh_token') {
                const refreshToken = utils.sanitizeString(req.body?.refresh_token, 255);
                if (!refreshToken) {
                    return res.status(400).json({ error: 'invalid_request' });
                }

                const refreshRow = await alexaCore.findAlexaRefreshTokenRow(refreshToken);
                if (!refreshRow) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }

                const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [refreshRow.user_id]);
                if (!user || !user.alexa_enabled || !utils.isAccessEnabled(user.status)) {
                    // If the user got disabled between issue and refresh,
                    // the existing access tokens become unrenewable. Alexa
                    // surfaces this as a re-link prompt to the customer.
                    return res.status(403).json({ error: 'access_denied' });
                }

                const tokens = await alexaCore.issueAlexaTokensForUser(user.id, refreshToken);
                return res.status(200).json({
                    access_token: tokens.accessToken,
                    refresh_token: tokens.refreshToken, // same as input — by contract
                    token_type: 'bearer',
                    expires_in: tokens.expiresIn
                });
            }

            return res.status(400).json({ error: 'unsupported_grant_type' });
        })
    );

    return router;
};

// Exposed for tests so the redirect-uri allow-list logic can be exercised
// without standing up the whole Express router.
module.exports._test = { isTrustedAlexaRedirectUri, buildLoginRedirect };
