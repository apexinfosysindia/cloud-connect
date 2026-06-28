const express = require('express');

// Customer SSO routes (Google / Microsoft / Apple). Thin HTTP layer over
// lib/sso.js: this file owns request/response shape, redirects, and error → URL
// mapping; lib/sso.js owns the OIDC mechanics, token verification, and the
// resolve-or-create-user transaction.
//
// Flow: GET /:provider/start → provider consent → GET|POST /:provider/callback
// → resolve/create user → set portal session cookie → redirect to /?sso=1,
// where public/account.js hydrates the dashboard from the cookie.
module.exports = function ({ utils, sso }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    // Land SSO failures back on the login screen with a stable, non-leaky code
    // the frontend can translate to a friendly message. We never echo provider
    // internals or email addresses into the URL.
    function fail(res, code, ret) {
        const path = sso.safeReturnPath(ret) || '/';
        const base = path.startsWith('/login') ? path.split('?')[0] : '/login';
        return res.redirect(`${base}?sso_error=${encodeURIComponent(code)}`);
    }

    // Advertise which provider buttons to render. Public + unauthenticated by
    // design (it reveals only which integrations are configured, no secrets),
    // and polled on every login/signup page load — hence it must stay on the
    // relaxed general-API limiter, never the strict auth bucket.
    router.get(
        '/api/auth/sso/providers',
        asyncHandler((req, res) => {
            res.setHeader('Cache-Control', 'no-store');
            res.status(200).json({ providers: sso.enabledProviders() });
        })
    );

    // Kick off the flow: build PKCE + state + nonce, stash them in the signed
    // tx cookie, and redirect the browser to the provider's own consent page.
    router.get(
        '/api/auth/sso/:provider/start',
        asyncHandler(async (req, res) => {
            const providerId = String(req.params.provider || '');
            if (!sso.isProviderEnabled(providerId)) {
                return res.status(404).send('SSO provider not available');
            }

            // `ret` lets a deep link (e.g. an OAuth-linking intent) resume after
            // login; sanitized to a same-origin path inside lib/sso.
            const ret = typeof req.query.ret === 'string' ? req.query.ret : '/';

            try {
                const { url, tx } = await sso.buildAuthorizationRequest(providerId, ret);
                sso.setTxCookie(res, tx);
                return res.redirect(url);
            } catch (err) {
                console.error(`SSO start error [${providerId}]:`, err.message);
                return fail(res, 'sso_unavailable', ret);
            }
        })
    );

    // Provider returns here. Google/Microsoft use GET (query params); Apple uses
    // POST (response_mode=form_post). Both share one handler — callbackParams in
    // lib/sso reads from query or body as appropriate.
    const handleCallback = asyncHandler(async (req, res) => {
        const providerId = String(req.params.provider || '');
        if (!sso.isProviderEnabled(providerId)) {
            return res.status(404).send('SSO provider not available');
        }

        const tx = sso.readTx(req);
        sso.clearTxCookie(res); // single-use: clear before doing anything else.

        // Missing/expired/tampered tx, or a provider mismatch, means the request
        // didn't originate from our /start (CSRF) or the user dawdled past the
        // 10-min TTL. Reject without attempting a token exchange.
        if (!tx || tx.provider !== providerId) {
            return fail(res, 'sso_expired', tx && tx.ret);
        }

        // The provider may itself report an error (user denied consent, etc.).
        const providerError = req.query?.error || req.body?.error;
        if (providerError) {
            console.warn(`SSO provider error [${providerId}]:`, String(providerError).slice(0, 100));
            return fail(res, 'sso_denied', tx.ret);
        }

        let claims;
        try {
            // Verifies signature (JWKS), issuer, audience, expiry, nonce, state,
            // and PKCE — all inside lib/sso via openid-client.
            claims = await sso.exchangeCallback(providerId, req, tx);
        } catch (err) {
            console.error(`SSO callback exchange error [${providerId}]:`, err.message);
            return fail(res, 'sso_failed', tx.ret);
        }

        let result;
        try {
            result = await sso.resolveOrCreateUser(claims, providerId);
        } catch (err) {
            if (err.code === 'sso_email_unverified') {
                return fail(res, 'email_unverified', tx.ret);
            }
            console.error(`SSO resolve-user error [${providerId}]:`, err.message);
            return fail(res, 'sso_failed', tx.ret);
        }

        sso.establishSession(res, result.user);

        // Hand back to the SPA with ?sso=1 so account.js knows to hydrate from
        // the freshly-set cookie (it otherwise only reads localStorage).
        const ret = sso.safeReturnPath(tx.ret);
        const sep = ret.includes('?') ? '&' : '?';
        return res.redirect(`${ret}${sep}sso=1`);
    });

    router.get('/api/auth/sso/:provider/callback', handleCallback);
    router.post('/api/auth/sso/:provider/callback', handleCallback);

    return router;
};
