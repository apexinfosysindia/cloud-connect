const express = require('express');

module.exports = function ({ dbGet, dbRun, dbTransaction, config, utils, auth, googleCore, homegraph }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.get(
        '/api/google/home/oauth',
        asyncHandler(async (req, res) => {
            const clientId = req.query?.client_id;
            const redirectUri = req.query?.redirect_uri;
            const state = req.query?.state;

            const portalTokenRaw = req.query?.portal_session_token;
            const queryPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
            const cookiePortalToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const portalToken = cookiePortalToken || queryPortalToken;

            if (!clientId || !redirectUri) {
                return res.status(400).send('Missing OAuth parameters');
            }

            if (!config.GOOGLE_HOME_CLIENT_ID || !config.GOOGLE_HOME_CLIENT_SECRET) {
                return res.status(503).send('Google Home OAuth is not configured');
            }

            if (clientId !== config.GOOGLE_HOME_CLIENT_ID) {
                return res.status(401).send('Invalid client_id');
            }

            if (!utils.isTrustedGoogleRedirectUri(redirectUri)) {
                return res.status(400).send('Invalid redirect_uri');
            }

            const forceCustomerLogin = req.hostname !== config.CUSTOMER_PORTAL_HOST || req.query?.from_cookie !== '1';
            if (!portalToken) {
                const loginRedirect = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
                if (forceCustomerLogin) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${loginRedirect}`);
                }
                return res.redirect(loginRedirect);
            }

            const session = auth.verifyPortalSessionToken(portalToken);
            if (!session) {
                const loginRedirect = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
                if (forceCustomerLogin) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${loginRedirect}`);
                }
                return res.redirect(loginRedirect);
            }

            const callbackUrl = new URL(redirectUri);
            const consentChallenge = encodeURIComponent(
                JSON.stringify({
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    state,
                    portal_session_token: portalToken
                })
            );

            if (req.query?.error) {
                callbackUrl.searchParams.set('error', utils.sanitizeString(req.query.error, 120) || 'access_denied');
                callbackUrl.searchParams.set('state', state);
                return res.redirect(callbackUrl.toString());
            }

            if (req.query?.deny === '1') {
                callbackUrl.searchParams.set('error', 'access_denied');
                callbackUrl.searchParams.set('state', state);
                return res.redirect(callbackUrl.toString());
            }

            if (req.query?.debug === '1') {
                return res.status(200).json({
                    ok: true,
                    stage: 'authorized',
                    email: session.email,
                    redirect_uri: redirectUri,
                    state
                });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).send('Account not found');
            }

            if (!auth.portalTokenEpochMatches(session, user)) {
                const loginRedirect = `/login.html?google_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
                if (forceCustomerLogin) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${loginRedirect}`);
                }
                return res.redirect(loginRedirect);
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).send('Account is not active for Google Home');
            }

            if (req.query?.approved !== '1') {
                const consentUrl = `/login.html?google_oauth=1&google_oauth_consent=1&oauth_challenge=${consentChallenge}`;
                if (req.hostname !== config.CUSTOMER_PORTAL_HOST) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${consentUrl}`);
                }
                return res.redirect(consentUrl);
            }

            if (!user.google_home_enabled) {
                await dbRun(`UPDATE users SET google_home_enabled = 1 WHERE id = ?`, [user.id]);
                user.google_home_enabled = 1;
            }

            const authCode = googleCore.generateGoogleOAuthCode();
            const nowIso = new Date().toISOString();
            const expiresAt = new Date(Date.now() + googleCore.getGoogleAuthCodeTtlSeconds() * 1000).toISOString();

            await dbTransaction(async ({ dbRun: txRun }) => {
                await txRun(
                    `
                INSERT INTO google_home_auth_codes (
                    user_id,
                    code_hash,
                    redirect_uri,
                    scopes,
                    expires_at,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `,
                    [user.id, utils.hashSecret(authCode), redirectUri, 'google_assistant', expiresAt, nowIso]
                );

                await txRun(
                    `
                UPDATE users
                SET google_home_linked = 1
                WHERE id = ?
            `,
                    [user.id]
                );
            });

            homegraph.scheduleGoogleRequestSyncForUser(user.id, 'oauth_linked');
            homegraph.scheduleGoogleReportStateForUser(user.id, { force: true });

            callbackUrl.searchParams.set('code', authCode);
            callbackUrl.searchParams.set('state', state);
            return res.redirect(callbackUrl.toString());
        })
    );

    router.post(
        '/api/google/home/oauth/continue',
        asyncHandler(async (req, res) => {
            const clientId = utils.sanitizeString(req.body?.client_id, 255);
            const redirectUri = utils.sanitizeString(req.body?.redirect_uri, 1000);
            const state = utils.sanitizeString(req.body?.state, 1000) || '';
            const portalTokenRaw = req.body?.portal_session_token;
            const bodyPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
            const cookiePortalToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const portalToken = cookiePortalToken || bodyPortalToken;

            if (!clientId || !redirectUri || !portalToken) {
                return res.status(400).json({ error: 'missing_oauth_parameters' });
            }

            if (!config.GOOGLE_HOME_CLIENT_ID || !config.GOOGLE_HOME_CLIENT_SECRET) {
                return res.status(503).json({ error: 'google_oauth_not_configured' });
            }

            if (clientId !== config.GOOGLE_HOME_CLIENT_ID) {
                return res.status(401).json({ error: 'invalid_client_id' });
            }

            const session = auth.verifyPortalSessionToken(portalToken);
            if (!session) {
                return res.status(401).json({ error: 'invalid_portal_session' });
            }

            auth.setPortalSessionCookie(res, portalToken);

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).json({ error: 'account_not_found' });
            }

            if (!auth.portalTokenEpochMatches(session, user)) {
                return res.status(401).json({ error: 'invalid_portal_session' });
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).json({ error: 'account_not_active' });
            }

            if (!user.google_home_enabled) {
                await dbRun(`UPDATE users SET google_home_enabled = 1 WHERE id = ?`, [user.id]);
                user.google_home_enabled = 1;
            }

            const authorizeUrl = new URL('/api/google/home/oauth', `${req.protocol}://${req.get('host')}`);
            authorizeUrl.searchParams.set('client_id', clientId);
            authorizeUrl.searchParams.set('redirect_uri', redirectUri);
            authorizeUrl.searchParams.set('response_type', 'code');
            authorizeUrl.searchParams.set('state', state);
            authorizeUrl.searchParams.set('portal_session_token', portalToken);

            return res.status(200).json({
                ok: true,
                redirect_url: authorizeUrl.toString()
            });
        })
    );

    router.get(
        '/api/google/home/oauth-debug',
        asyncHandler(async (req, res) => {
            if (!config.GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
                return res.status(404).json({ error: 'not_found' });
            }

            const clientId = utils.sanitizeString(req.query?.client_id, 255);
            const redirectUri = utils.sanitizeString(req.query?.redirect_uri, 1000);
            const state = utils.sanitizeString(req.query?.state, 1000) || '';
            const portalTokenRaw = req.query?.portal_session_token;
            const queryPortalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';
            const cookiePortalToken = req.cookies?.[config.PORTAL_SESSION_COOKIE_NAME] || '';
            const portalToken = cookiePortalToken || queryPortalToken;

            if (!clientId || !redirectUri) {
                return res.status(400).json({ ok: false, error: 'missing_oauth_params' });
            }

            if (!utils.isTrustedGoogleRedirectUri(redirectUri)) {
                return res.status(400).json({ ok: false, error: 'invalid_redirect_uri' });
            }

            const payload = {
                ok: true,
                host: req.get('host') || null,
                origin: req.get('origin') || null,
                from_cookie: req.query?.from_cookie === '1',
                has_cookie_header: Boolean(req.get('cookie')),
                has_google_client_id: Boolean(config.GOOGLE_HOME_CLIENT_ID),
                has_google_client_secret: Boolean(config.GOOGLE_HOME_CLIENT_SECRET),
                client_id_matches: clientId === config.GOOGLE_HOME_CLIENT_ID,
                redirect_uri: redirectUri,
                state,
                has_portal_token: Boolean(portalToken),
                has_cookie_portal_token: Boolean(cookiePortalToken),
                has_query_portal_token: Boolean(queryPortalToken),
                portal_token_has_dot: portalToken.includes('.'),
                portal_token_parts: portalToken ? portalToken.split('.').length : 0,
                portal_token_preview: portalToken ? `${portalToken.slice(0, 24)}...` : null,
                portal_token_length: portalToken ? portalToken.length : 0,
                cookie_name: config.PORTAL_SESSION_COOKIE_NAME,
                cookie_secure: config.PORTAL_SESSION_COOKIE_SECURE,
                cookie_domain: config.PORTAL_SESSION_COOKIE_DOMAIN
            };

            if (!portalToken) {
                return res.status(200).json(payload);
            }

            const session = auth.verifyPortalSessionToken(portalToken);
            if (!session) {
                return res.status(200).json({ ...payload, portal_session_valid: false });
            }

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(200).json({ ...payload, portal_session_valid: true, user_found: false });
            }

            return res.status(200).json({
                ...payload,
                portal_session_valid: true,
                user_found: true,
                user_email: user.email,
                user_status: user.status,
                google_home_enabled: Boolean(user.google_home_enabled)
            });
        })
    );

    router.post('/api/google/home/oauth-debug-cookie', (req, res) => {
        if (!config.GOOGLE_DEBUG_ENDPOINTS_ENABLED) {
            return res.status(404).json({ error: 'not_found' });
        }

        const portalTokenRaw = req.body?.portal_session_token;
        const portalToken = typeof portalTokenRaw === 'string' ? portalTokenRaw.trim() : '';

        if (!portalToken) {
            return res.status(400).json({ ok: false, error: 'portal_session_token_required' });
        }

        auth.setPortalSessionCookie(res, portalToken);
        return res.status(200).json({
            ok: true,
            cookie_name: config.PORTAL_SESSION_COOKIE_NAME,
            cookie_domain: config.PORTAL_SESSION_COOKIE_DOMAIN,
            cookie_secure: config.PORTAL_SESSION_COOKIE_SECURE,
            token_has_dot: portalToken.includes('.'),
            token_parts: portalToken.split('.').length
        });
    });

    router.post(
        '/api/google/home/token',
        asyncHandler(async (req, res) => {
            const grantType = utils.sanitizeString(req.body?.grant_type, 64);
            const clientId = utils.sanitizeString(req.body?.client_id, 255);
            const clientSecret = utils.sanitizeString(req.body?.client_secret, 255);

            if (!config.GOOGLE_HOME_CLIENT_ID || !config.GOOGLE_HOME_CLIENT_SECRET) {
                return res.status(503).json({ error: 'google_oauth_not_configured' });
            }

            if (clientId !== config.GOOGLE_HOME_CLIENT_ID || clientSecret !== config.GOOGLE_HOME_CLIENT_SECRET) {
                return res.status(401).json({ error: 'invalid_client' });
            }

            if (grantType === 'authorization_code') {
                const code = utils.sanitizeString(req.body?.code, 255);
                const redirectUri = utils.sanitizeString(req.body?.redirect_uri, 1000);
                if (!code || !redirectUri) {
                    return res.status(400).json({ error: 'invalid_request' });
                }

                const linkedUser = await googleCore.findUserByGoogleAuthCode(code, redirectUri);
                if (!linkedUser) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }

                if (!linkedUser.google_home_enabled || !utils.isAccessEnabled(linkedUser.status)) {
                    return res.status(403).json({ error: 'access_denied' });
                }

                await dbRun(
                    `
                    UPDATE google_home_auth_codes
                    SET consumed_at = ?
                    WHERE id = ?
                `,
                    [new Date().toISOString(), linkedUser.oauth_code_id]
                );

                const tokenResponse = await googleCore.issueGoogleTokensForUser(linkedUser.id);
                return res.status(200).json(tokenResponse);
            }

            if (grantType === 'refresh_token') {
                const refreshToken = utils.sanitizeString(req.body?.refresh_token, 255);
                if (!refreshToken) {
                    return res.status(400).json({ error: 'invalid_request' });
                }

                const refreshRow = await googleCore.findGoogleRefreshTokenRow(refreshToken);
                if (!refreshRow) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }

                const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [refreshRow.user_id]);
                if (!user || !user.google_home_enabled || !utils.isAccessEnabled(user.status)) {
                    return res.status(403).json({ error: 'access_denied' });
                }

                const tokenResponse = await googleCore.issueGoogleTokensForUser(user.id, refreshToken);
                return res.status(200).json(tokenResponse);
            }

            return res.status(400).json({ error: 'unsupported_grant_type' });
        })
    );

    return router;
};
