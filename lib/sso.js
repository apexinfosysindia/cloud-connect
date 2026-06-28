const crypto = require('crypto');
const { Issuer, generators, custom } = require('openid-client');

// Customer SSO / social sign-in service (Google, Microsoft, Apple).
//
// This is the OIDC *client* side of the app — the mirror image of the Google
// Home / Alexa OAuth code, where the portal is the provider. Here the customer
// is redirected to the provider's OWN consent screen and we consume the result.
// We integrate directly with each provider's discovery + token endpoints; there
// is no third-party broker (Auth0/Okta-hosted/etc.) in the path.
//
// Token verification (signature, issuer, audience, expiry, nonce) is delegated
// to `openid-client` (panva) — a security boundary we deliberately do NOT
// hand-roll. We reuse the existing portal-session minting (lib/auth.js) for the
// resulting login, so an SSO session is byte-for-byte identical to a password
// or passkey session (same cookie, same 7-day HMAC token, same session_epoch
// invalidation). Nothing about sessions is reimplemented here.
module.exports = function ({ config, utils, auth, dbTransaction }) {
    // Give discovery/token HTTP calls a more forgiving timeout than the 3.5s
    // library default — provider metadata endpoints can be slow on a cold DNS.
    custom.setHttpOptionsDefaults({ timeout: 10000 });

    const SSO = config.SSO;
    const TX_COOKIE_NAME = 'apx_sso_tx';
    const TX_TTL_MS = 10 * 60 * 1000; // 10 minutes: ample to complete consent.
    const SENTINEL_PREFIX = '!sso:';

    const normEmail = (e) =>
        String(e || '')
            .trim()
            .toLowerCase();

    function provider(providerId) {
        return SSO.providers[providerId];
    }

    function isProviderEnabled(providerId) {
        const p = provider(providerId);
        return Boolean(p && p.enabled);
    }

    // The buttons the frontend should render. Only providers whose credentials
    // are present appear, so an un-provisioned deploy advertises nothing.
    function enabledProviders() {
        return Object.values(SSO.providers)
            .filter((p) => p.enabled)
            .map((p) => ({ id: p.id, label: p.label }));
    }

    function redirectUri(providerId) {
        return `${SSO.baseUrl}/api/auth/sso/${providerId}/callback`;
    }

    // ── Apple client_secret ────────────────────────────────────────────────
    // Apple does not issue a static client secret. Instead the relying party
    // mints a short-lived ES256 JWT signed with the developer key (Team ID +
    // Key ID + PKCS8 private key), presented as the client_secret at the token
    // endpoint. We sign with node:crypto (no extra dep). ES256 over JWS needs
    // the raw r||s signature, so dsaEncoding MUST be 'ieee-p1363' (the default
    // 'der' would produce an invalid JWS signature Apple rejects).
    const b64url = (input) => Buffer.from(input).toString('base64url');

    function appleClientSecret() {
        const p = provider('apple');
        const now = Math.floor(Date.now() / 1000);
        const header = { alg: 'ES256', kid: p.keyId, typ: 'JWT' };
        const payload = {
            iss: p.teamId,
            iat: now,
            exp: now + 300, // Apple caps client_secret lifetime at 6 months; 5 min is plenty.
            aud: 'https://appleid.apple.com',
            sub: p.clientId
        };
        const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
        const signature = crypto.sign('SHA256', Buffer.from(signingInput), {
            key: p.privateKey,
            dsaEncoding: 'ieee-p1363'
        });
        return `${signingInput}.${b64url(signature)}`;
    }

    // ── Provider client construction ───────────────────────────────────────
    // Discovery (the slow network round-trip to /.well-known) is memoized per
    // provider; the Client itself is cheap and built per-call. That matters for
    // Apple, whose client_secret expires every 5 minutes — a cached Client
    // would carry a stale secret, so we always reconstruct with a fresh one.
    const issuerCache = new Map();

    function getIssuer(providerId) {
        if (!issuerCache.has(providerId)) {
            const p = provider(providerId);
            const discovered = Issuer.discover(p.issuer).catch((err) => {
                issuerCache.delete(providerId); // don't cache a failed discovery
                throw err;
            });
            issuerCache.set(providerId, discovered);
        }
        return issuerCache.get(providerId);
    }

    async function getClient(providerId) {
        const p = provider(providerId);
        if (!p || !p.enabled) {
            const err = new Error(`sso_provider_disabled:${providerId}`);
            err.code = 'sso_provider_disabled';
            throw err;
        }
        const issuer = await getIssuer(providerId);
        const clientSecret = providerId === 'apple' ? appleClientSecret() : p.clientSecret;
        return new issuer.Client({
            client_id: p.clientId,
            client_secret: clientSecret,
            redirect_uris: [redirectUri(providerId)],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_post'
        });
    }

    // ── Transaction cookie (state/nonce/PKCE carrier) ──────────────────────
    // The verifier/state/nonce generated at /start must survive the round-trip
    // to the provider and back. We stash them in a short-lived HMAC-signed
    // cookie rather than server state — signed with the SAME portal secret used
    // for session tokens (auth.signPortalValue), so there's no new key to
    // manage. The cookie holds no secrets beyond single-use CSRF/PKCE material.
    function signTxCookie(obj) {
        const payload = Buffer.from(JSON.stringify(obj)).toString('base64url');
        return `${payload}.${auth.signPortalValue(payload)}`;
    }

    function verifyTxCookie(token) {
        if (!token || !utils.hasExactlyOneDot(token)) {
            return null;
        }
        const [payload, signature] = token.split('.');
        const expected = auth.signPortalValue(payload);
        const expectedBuf = Buffer.from(expected);
        const signatureBuf = Buffer.from(signature || '');
        if (expectedBuf.length !== signatureBuf.length) {
            return null;
        }
        if (!crypto.timingSafeEqual(expectedBuf, signatureBuf)) {
            return null;
        }
        try {
            const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
            if (!decoded || !decoded.exp || decoded.exp < Date.now()) {
                return null;
            }
            return decoded;
        } catch (_err) {
            return null;
        }
    }

    // CRITICAL: SameSite=None (NOT Lax). Apple returns the callback as a
    // cross-site POST (response_mode=form_post); a Lax cookie is NOT sent on a
    // cross-site POST, which would lose the PKCE verifier + state and break
    // every Apple login. None requires Secure, so SSO testing needs https (a
    // tunnel locally). The portal session cookie stays Lax — it's set on the
    // same-site callback response and read on the same-site /?sso=1 navigation.
    function setTxCookie(res, tx) {
        res.cookie(TX_COOKIE_NAME, signTxCookie(tx), {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            path: '/',
            maxAge: TX_TTL_MS
        });
    }

    function clearTxCookie(res) {
        res.clearCookie(TX_COOKIE_NAME, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            path: '/'
        });
    }

    function readTx(req) {
        return verifyTxCookie(req.cookies?.[TX_COOKIE_NAME] || '');
    }

    // Open-redirect guard for the post-login return path. Accept ONLY a
    // same-origin absolute path; reject absolute URLs and protocol-relative
    // ("//evil.com") values that browsers treat as cross-origin.
    function safeReturnPath(ret) {
        if (typeof ret !== 'string' || !ret) return '/';
        if (!ret.startsWith('/') || ret.startsWith('//')) return '/';
        return ret;
    }

    // ── /start: build the provider authorization URL + the tx payload ──────
    async function buildAuthorizationRequest(providerId, ret) {
        const p = provider(providerId);
        const client = await getClient(providerId);
        const codeVerifier = generators.codeVerifier();
        const codeChallenge = generators.codeChallenge(codeVerifier);
        const state = generators.state();
        const nonce = generators.nonce();

        const params = {
            scope: p.scope,
            redirect_uri: redirectUri(providerId),
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            state,
            nonce
        };
        // Apple requires form_post to return the email/name claims (and so to
        // POST the authorization code back to us).
        if (providerId === 'apple') {
            params.response_mode = 'form_post';
        }

        const url = client.authorizationUrl(params);
        const tx = {
            provider: providerId,
            code_verifier: codeVerifier,
            state,
            nonce,
            ret: safeReturnPath(ret),
            exp: Date.now() + TX_TTL_MS
        };
        return { url, tx };
    }

    // ── /callback: verify the response and resolve the claims ──────────────
    // Returns the verified ID-token claims. The route is responsible for having
    // already validated tx.provider === the URL provider and tx freshness.
    async function exchangeCallback(providerId, req, tx) {
        const client = await getClient(providerId);
        // callbackParams reads req.query for GET and req.body for POST (Apple);
        // the global express.urlencoded parser populates req.body.
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(redirectUri(providerId), params, {
            code_verifier: tx.code_verifier,
            state: tx.state,
            nonce: tx.nonce
        });
        return tokenSet.claims();
    }

    // ── resolve-or-create the local user for a verified SSO identity ───────
    // Runs in ONE transaction. db-helpers serializes all transactions through a
    // single BEGIN IMMEDIATE chain, so two concurrent first-logins can't race:
    // the second transaction only begins after the first commits, by which time
    // step 1 finds the freshly-inserted identity. Hence no explicit
    // UNIQUE(provider,subject) retry is needed (the constraint is a backstop).
    function ssoSentinelPassword() {
        // A value that can never be a bcrypt hash, so bcrypt.compare() always
        // returns false → every password-gated path safely denies a pure-SSO
        // user. Avoids relaxing users.password NOT NULL (a SQLite table rebuild).
        return SENTINEL_PREFIX + crypto.randomBytes(24).toString('hex');
    }

    function resolveOrCreateUser(claims, providerId) {
        const subject = String(claims.sub || '');
        const email = normEmail(claims.email);
        // Apple-verified emails are implicitly trusted (Apple only returns the
        // email on first consent and guarantees ownership). Google/Microsoft
        // expose email_verified explicitly — require it to be strictly true.
        const emailVerified = providerId === 'apple' ? true : claims.email_verified === true;

        return dbTransaction(async ({ dbGet, dbRun }) => {
            // A missing subject means a malformed ID token — never trust it.
            // Thrown inside the transaction so it surfaces as a rejection (the
            // route awaits this) rather than a synchronous throw.
            if (!subject) {
                const err = new Error('sso_no_subject');
                err.code = 'sso_no_subject';
                throw err;
            }

            // 1. Returning identity → load + return the already-linked account.
            const existing = await dbGet(
                `SELECT u.* FROM user_oauth_identities i
                 JOIN users u ON u.id = i.user_id
                 WHERE i.provider = ? AND i.subject = ?`,
                [providerId, subject]
            );
            if (existing) {
                return { user: existing, created: false, linked: false };
            }

            // 2. A NEW identity may only be created/linked from a verified email
            //    — this is the anti-account-takeover guard. Without it, an IdP
            //    that let a user assert an arbitrary unverified email could hijack
            //    a local account by matching its address.
            if (!email || !emailVerified) {
                const err = new Error('sso_email_unverified');
                err.code = 'sso_email_unverified';
                throw err;
            }

            // 3a. Email matches an existing account → auto-link (the IdP just
            //     proved ownership of this address).
            const byEmail = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
            if (byEmail) {
                await dbRun(
                    `INSERT INTO user_oauth_identities (user_id, provider, subject, email)
                     VALUES (?, ?, ?, ?)`,
                    [byEmail.id, providerId, subject, email]
                );
                // If the local account had never verified its email, the IdP's
                // proof retroactively verifies it (and unblocks checkout).
                if (!byEmail.email_verified) {
                    await dbRun(`UPDATE users SET email_verified = 1 WHERE id = ?`, [byEmail.id]);
                    byEmail.email_verified = 1;
                }
                return { user: byEmail, created: false, linked: true };
            }

            // 3b. Brand-new account. Lands payment_pending + email_verified=1 +
            //     null subdomain — identical to a password signup minus the
            //     password — so the existing dashboard drives subdomain choice
            //     and Razorpay checkout. No billing logic is duplicated here.
            const insert = await dbRun(
                `INSERT INTO users (email, password, subdomain, status, email_verified)
                 VALUES (?, ?, NULL, 'payment_pending', 1)`,
                [email, ssoSentinelPassword()]
            );
            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insert.lastID]);
            await dbRun(
                `INSERT INTO user_oauth_identities (user_id, provider, subject, email)
                 VALUES (?, ?, ?, ?)`,
                [user.id, providerId, subject, email]
            );
            return { user, created: true, linked: false };
        });
    }

    // ── establish the portal session (mirror of routes/auth.js finishLogin) ─
    // Mints the exact same session cookie + token a password/passkey login
    // would. No email re-verification branch: SSO users are always
    // email_verified=1, so finishLogin's re-send path would be a no-op anyway.
    function establishSession(res, user) {
        const token = auth.createPortalSessionToken(user.email, user.session_epoch);
        auth.setPortalSessionCookie(res, token);
        return token;
    }

    return {
        TX_COOKIE_NAME,
        enabledProviders,
        isProviderEnabled,
        buildAuthorizationRequest,
        setTxCookie,
        clearTxCookie,
        readTx,
        safeReturnPath,
        exchangeCallback,
        resolveOrCreateUser,
        establishSession,
        // exported for unit-level testing / introspection
        appleClientSecret,
        redirectUri
    };
};
