const express = require('express');

module.exports = function ({ dbGet, dbRun, dbTransaction, config, utils, auth, alexaCore, alexaEventGateway }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.get(
        '/api/alexa/oauth',
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

            if (!config.ALEXA_CLIENT_ID || !config.ALEXA_CLIENT_SECRET) {
                return res.status(503).send('Alexa OAuth is not configured');
            }

            if (clientId !== config.ALEXA_CLIENT_ID) {
                return res.status(401).send('Invalid client_id');
            }

            if (!utils.isTrustedAlexaRedirectUri(redirectUri)) {
                return res.status(400).send('Invalid redirect_uri');
            }

            const forceCustomerLogin = req.hostname !== config.CUSTOMER_PORTAL_HOST || req.query?.from_cookie !== '1';
            if (!portalToken) {
                const loginRedirect = `/login.html?alexa_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
                if (forceCustomerLogin) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${loginRedirect}`);
                }
                return res.redirect(loginRedirect);
            }

            const session = auth.verifyPortalSessionToken(portalToken);
            if (!session) {
                const loginRedirect = `/login.html?alexa_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
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

            const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [session.email]);
            if (!user) {
                return res.status(404).send('Account not found');
            }

            if (!auth.portalTokenEpochMatches(session, user)) {
                const loginRedirect = `/login.html?alexa_oauth=1&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)}`;
                if (forceCustomerLogin) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${loginRedirect}`);
                }
                return res.redirect(loginRedirect);
            }

            if (!utils.isAccessEnabled(user.status)) {
                return res.status(403).send('Account is not active for Alexa');
            }

            if (req.query?.approved !== '1') {
                const consentUrl = `/login.html?alexa_oauth=1&alexa_oauth_consent=1&oauth_challenge=${consentChallenge}`;
                if (req.hostname !== config.CUSTOMER_PORTAL_HOST) {
                    return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${consentUrl}`);
                }
                return res.redirect(consentUrl);
            }

            if (!user.alexa_enabled) {
                await dbRun(`UPDATE users SET alexa_enabled = 1 WHERE id = ?`, [user.id]);
                user.alexa_enabled = 1;
            }

            const authCode = alexaCore.generateAlexaOAuthCode();
            const nowIso = new Date().toISOString();
            const expiresAt = new Date(Date.now() + alexaCore.getAlexaAuthCodeTtlSeconds() * 1000).toISOString();

            await dbTransaction(async ({ dbRun: txRun }) => {
                await txRun(
                    `
                        INSERT INTO alexa_auth_codes (
                            user_id,
                            code_hash,
                            redirect_uri,
                            scopes,
                            expires_at,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    `,
                    [user.id, utils.hashSecret(authCode), redirectUri, 'alexa::async_event', expiresAt, nowIso]
                );

                await txRun(`UPDATE users SET alexa_linked = 1 WHERE id = ?`, [user.id]);
            });

            if (alexaEventGateway?.queueAlexaAddOrUpdateReport) {
                try {
                    alexaEventGateway.queueAlexaAddOrUpdateReport(user.id, null, 'oauth_linked');
                } catch (error) {
                    console.warn('ALEXA OAUTH QUEUE ADDORUPDATE ERROR:', error?.message || error);
                }
            }

            callbackUrl.searchParams.set('code', authCode);
            callbackUrl.searchParams.set('state', state);
            return res.redirect(callbackUrl.toString());
        })
    );

    router.post(
        '/api/alexa/oauth/continue',
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

            if (!config.ALEXA_CLIENT_ID || !config.ALEXA_CLIENT_SECRET) {
                return res.status(503).json({ error: 'alexa_oauth_not_configured' });
            }

            if (clientId !== config.ALEXA_CLIENT_ID) {
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

            if (!user.alexa_enabled) {
                await dbRun(`UPDATE users SET alexa_enabled = 1 WHERE id = ?`, [user.id]);
                user.alexa_enabled = 1;
            }

            const authorizeUrl = new URL('/api/alexa/oauth', `${req.protocol}://${req.get('host')}`);
            authorizeUrl.searchParams.set('client_id', clientId);
            authorizeUrl.searchParams.set('redirect_uri', redirectUri);
            authorizeUrl.searchParams.set('response_type', 'code');
            authorizeUrl.searchParams.set('state', state);
            authorizeUrl.searchParams.set('approved', '1');
            authorizeUrl.searchParams.set('portal_session_token', portalToken);

            return res.status(200).json({
                ok: true,
                redirect_url: authorizeUrl.toString()
            });
        })
    );

    router.post(
        '/api/alexa/token',
        asyncHandler(async (req, res) => {
            const grantType = utils.sanitizeString(req.body?.grant_type, 64);
            const clientId = utils.sanitizeString(req.body?.client_id, 255);
            const clientSecret = utils.sanitizeString(req.body?.client_secret, 255);

            if (!config.ALEXA_CLIENT_ID || !config.ALEXA_CLIENT_SECRET) {
                return res.status(503).json({ error: 'alexa_oauth_not_configured' });
            }

            if (clientId !== config.ALEXA_CLIENT_ID || clientSecret !== config.ALEXA_CLIENT_SECRET) {
                return res.status(401).json({ error: 'invalid_client' });
            }

            if (grantType === 'authorization_code') {
                const code = utils.sanitizeString(req.body?.code, 255);
                const redirectUri = utils.sanitizeString(req.body?.redirect_uri, 1000);
                if (!code || !redirectUri) {
                    return res.status(400).json({ error: 'invalid_request' });
                }

                const linkedUser = await alexaCore.findUserByAlexaAuthCode(code, redirectUri);
                if (!linkedUser) {
                    return res.status(400).json({ error: 'invalid_grant' });
                }

                if (!linkedUser.alexa_enabled || !utils.isAccessEnabled(linkedUser.status)) {
                    return res.status(403).json({ error: 'access_denied' });
                }

                await dbRun(
                    `UPDATE alexa_auth_codes SET consumed_at = ? WHERE id = ?`,
                    [new Date().toISOString(), linkedUser.oauth_code_id]
                );

                const tokenResponse = await alexaCore.issueAlexaTokensForUser(linkedUser.id);
                return res.status(200).json(tokenResponse);
            }

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
                    return res.status(403).json({ error: 'access_denied' });
                }

                const tokenResponse = await alexaCore.issueAlexaTokensForUser(user.id, refreshToken);
                return res.status(200).json(tokenResponse);
            }

            return res.status(400).json({ error: 'unsupported_grant_type' });
        })
    );

    return router;
};
