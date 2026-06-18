const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Prevent unhandled errors from crashing the process (Caddy returns 502 when Node is down)
process.on('uncaughtException', (error) => {
    console.error('UNCAUGHT EXCEPTION (process kept alive):', error);
});
process.on('unhandledRejection', (reason) => {
    console.error('UNHANDLED REJECTION (process kept alive):', reason);
});

// --- Load lib modules ---
const config = require('./lib/config');
const utils = require('./lib/utils');
const db = require('./db');
const { dbGet, dbRun, dbAll, dbTransaction } = require('./lib/db-helpers')(db);

// Factory-initialized modules (dependency order matters)
const device = require('./lib/device')({ dbGet, dbRun, dbAll, config, utils });
const billing = require('./lib/billing')({
    dbGet,
    dbRun,
    dbAll,
    dbTransaction,
    config,
    utils,
    createUniqueAccessToken: device.createUniqueAccessToken
});

// Google Home modules (circular dep resolved via shared state.js)
const state = require('./lib/google-home/state');
const entityMapping = require('./lib/google-home/entity-mapping');
const homegraph = require('./lib/google-home/homegraph')({
    dbGet,
    dbRun,
    dbAll,
    config,
    utils,
    state,
    entityMapping
});
const googleCore = require('./lib/google-home/core')({
    dbGet,
    dbRun,
    dbAll,
    homegraph
});

// Wire the circular dependency: entity-mapping needs to check homegraph credentials
entityMapping.setHasGoogleHomegraphCredentials(() => homegraph.hasGoogleHomegraphCredentials());

// Alexa Smart Home modules (mirror of the Google block; built before auth
// because auth.requireAlexaBearer depends on alexaCore). Construction order:
// crypto → core → eventGateway, then back-fill core's eventGateway reference.
const alexaState = require('./lib/alexa/state');
const alexaEntityMapping = require('./lib/alexa/entity-mapping');
const alexaCrypto = require('./lib/alexa/crypto')({ config });
const alexaCore = require('./lib/alexa/core')({ dbGet, dbRun, dbAll, alexaCrypto });
const alexaEventGateway = require('./lib/alexa/event-gateway')({ dbGet, dbRun, dbAll, core: alexaCore });

// Auth depends on device, googleCore, and alexaCore, so it must be initialized after them
const auth = require('./lib/auth')({ dbGet, config, utils, device, googleCore, alexaCore });

// WebAuthn / passkey 2FA helper (owns credential + challenge persistence)
const webauthn = require('./lib/webauthn')({ dbGet, dbRun, dbAll, config, utils });

// Email module for verification and password reset flows
const email = require('./lib/email')({ dbGet, dbRun, config, utils });

// --- Express app setup ---
const app = express();

// Trust the first proxy hop (Caddy) so req.ip and X-Forwarded-For are honored.
// Without this, express-rate-limit throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR on
// every proxied request and 500s before route handlers run — which silently
// breaks Amazon's Alexa OAuth account-linking flow (Alexa always traverses
// Caddy; curl probes from outside Caddy don't, which is why this only shows up
// in production). Do NOT remove as "cleanup": it is load-bearing behind any
// reverse proxy that sets X-Forwarded-For.
app.set('trust proxy', 1);

app.use(cookieParser());

// Security headers
app.use(
    helmet({
        contentSecurityPolicy: false, // Disabled: static HTML pages use inline scripts/styles
        crossOriginEmbedderPolicy: false, // Disabled: pages load external resources (fonts, CDN scripts)
        crossOriginOpenerPolicy: false, // Disabled: Razorpay checkout uses popups for 3D Secure / UPI verification
        crossOriginResourcePolicy: false // Disabled: Razorpay checkout iframe loads cross-origin resources
    })
);

app.use(
    express.json({
        limit: '5mb',
        verify: (req, _res, buf) => {
            if (buf && buf.length > 0) {
                req.rawBody = buf.toString();
            }
        }
    })
);
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin) {
                callback(null, true);
                return;
            }

            if (config.ALLOWED_CORS_ORIGINS.length === 0) {
                callback(null, false);
                return;
            }

            callback(null, config.ALLOWED_CORS_ORIGINS.includes(origin));
        },
        credentials: true,
        methods: ['GET', 'POST', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization']
    })
);

// Body parse error handler (must be after body parsers, before routes)
app.use((error, _req, res, next) => {
    if (error?.type === 'entity.too.large') {
        return res.status(413).json({ error: 'payload_too_large' });
    }

    if (error instanceof SyntaxError && error?.status === 400 && 'body' in error) {
        return res.status(400).json({ error: 'invalid_json_payload' });
    }

    return next(error);
});

// --- Rate limiting ---
const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please try again later.' }
});

const signupRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 signups per hour per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many signup attempts. Please try again later.' }
});

const generalApiRateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 500, // 500 requests per minute per IP (bumped from 100 to accommodate
              // bulk dashboard operations that fan out to multiple entities)
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path.startsWith('/internal/'),
    message: { error: 'Too many requests. Please slow down.' }
});

const emailRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 email requests per 15 minutes per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many email requests. Please try again later.' }
});

app.use('/api/', generalApiRateLimiter);
// Identifier-first login is multi-step, and the steps are NOT equal:
//   • lookup + passkey/begin check no secret — they reveal an email's existence
//     (an accepted enumeration trade-off) and issue a public WebAuthn challenge.
//     They run on EVERY login attempt, and on shared/NAT'd IPs many distinct
//     users hit them, so they must stay on the generous general-API bucket
//     above. Holding them under the strict per-IP cap caused false "Too many
//     attempts" lockouts (a single passkey login alone spends lookup + begin +
//     verify = 3 of 10).
//   • password, otp/verify, passkey/verify each verify a secret (password, code,
//     assertion) and ARE the brute-force surface → strict bucket.
// app.use('/api/auth/login', …) prefix-matches every sub-route; inside the
// handler req.path is relative to that mount, so we let the two non-secret steps
// fall through (general-API limiter only) and apply the strict limiter to
// everything else — including the legacy bare POST /api/auth/login (req.path '/').
app.use('/api/auth/login', (req, res, next) => {
    if (req.path === '/lookup' || req.path === '/passkey/begin') {
        return next();
    }
    return authRateLimiter(req, res, next);
});
app.use('/api/admin/login', authRateLimiter);
app.use('/api/auth/signup', signupRateLimiter);
app.use('/api/auth/forgot-password', emailRateLimiter);
app.use('/api/auth/resend-verification', emailRateLimiter);
app.use('/api/auth/reset-password', authRateLimiter);
app.use('/api/auth/verify-email', authRateLimiter);

// Password-gated account-management endpoints. These all bcrypt.compare()
// against the user's password, so they're brute-force targets for anyone
// who hijacks a portal session token. Hold them under the strict auth
// limiter rather than the relaxed 500/min general API bucket.
app.use('/api/account/change-password', authRateLimiter);
app.use('/api/account/delete', authRateLimiter);
app.use('/api/account/cancel-subscription', authRateLimiter);

// --- Shared deps object for route factories ---
const deps = {
    dbGet,
    dbRun,
    dbAll,
    dbTransaction,
    config,
    utils,
    auth,
    webauthn,
    email,
    device,
    billing,
    googleCore,
    homegraph,
    entityMapping,
    state,
    // Alexa modules (route factories destructure `core`/`eventGateway`/`entityMapping`)
    core: alexaCore,
    eventGateway: alexaEventGateway,
    alexaEntityMapping,
    alexaState
};

// --- Register routes ---
// Canonical clean URLs: hide the .html extension everywhere. Any GET/HEAD for a
// /*.html path 301s to its extensionless form (/login.html → /login,
// /index.html → /). This covers old bookmarks, links inside already-sent emails,
// and someone typing the extension by hand — the bar never shows .html. The
// query string (e.g. ?token=…) is preserved so verify/reset links keep working.
// Must run before the pages router + static so it canonicalizes first.
app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return next();
    }
    if (!req.path.endsWith('.html')) {
        return next();
    }
    const base = req.path.slice(0, -'.html'.length);
    const cleanPath = base === '/index' ? '/' : base;
    const queryIndex = req.originalUrl.indexOf('?');
    const queryString = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : '';
    return res.redirect(301, cleanPath + queryString);
});

// The pages router MUST run before express.static. It applies host-based
// redirects (e.g. cloud.apexinfosys.in/admin → vista, /login → oasis) so the
// device/landing host never serves portal HTML off disk. If static ran first it
// would answer any page request by filename alone (via the `extensions` option
// below) — ignoring the hostname — and the redirects below would never fire.
app.use(require('./routes/pages')(deps));

// --- Static files (registered AFTER the pages router on purpose; see above) ---
// no-cache = "cache, but always revalidate before use". Express still sends
// ETag/Last-Modified, so unchanged files return a cheap 304 while a redeployed
// file is served fresh immediately — no content-hashing/build step needed, and
// no more stale account.js after a soft refresh. Nothing here is fingerprinted,
// so this applies uniformly (incl. the vendored webauthn bundle).
app.use(
    express.static(path.join(__dirname, 'public'), {
        index: false,
        // Serve /login from login.html on disk so URLs stay extensionless. The
        // 301 middleware above already bounced any explicit /login.html here.
        extensions: ['html'],
        setHeaders: (res) => {
            res.setHeader('Cache-Control', 'no-cache');
        }
    })
);

app.use(require('./routes/device-api')(deps));
app.use(require('./routes/admin-fleet')(deps));
app.use(require('./routes/auth')(deps));
app.use(require('./routes/webauthn')(deps));
app.use(require('./routes/admin-sudo')(deps));
app.use(require('./routes/billing')(deps));
app.use(require('./routes/admin')(deps));
app.use(require('./routes/internal')(deps));
app.use(require('./routes/google-home-portal')(deps));
app.use(require('./routes/google-home-oauth')(deps));
app.use(require('./routes/google-home-fulfillment')(deps));
app.use(require('./routes/google-home-device-api')(deps));
app.use(require('./routes/google-home-admin')(deps));

// Alexa routes share the deps object but need the Alexa entity-mapping bound to
// the `entityMapping` key the fulfillment factory destructures.
const alexaDeps = { ...deps, entityMapping: alexaEntityMapping };
app.use(require('./routes/alexa-oauth')(alexaDeps));
app.use(require('./routes/alexa-portal')(alexaDeps));
app.use(require('./routes/alexa-fulfillment')(alexaDeps));
app.use(require('./routes/alexa-device-api')(alexaDeps));

// --- Global error handler for uncaught route errors (used by asyncHandler) ---
app.use((error, _req, res, _next) => {
    console.error('UNHANDLED ROUTE ERROR:', error);
    if (!res.headersSent) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- Config validation (exit early if secrets are missing) ---
try {
    auth.getPortalSecret();
    auth.getAdminSecret();
} catch (error) {
    console.error('CRITICAL CONFIG ERROR:', error.message);
    process.exit(1);
}

// --- Start server ---
const PORT = process.env.PORT || 3000;

db.ready
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Cloud Portal API is running on http://localhost:${PORT}`);
            googleCore
                .ensureGoogleRuntimeSchemaReady()
                .then(() => {
                    console.log('Google runtime schema ready.');
                })
                .catch((error) => {
                    console.error('Google runtime schema migration failed:', error);
                });
            googleCore.startStaleEntityInterval();

            // Check for expired trial / admin-activated accounts every hour
            const EXPIRY_CHECK_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
            billing.expireOverdueAccounts().catch((err) => {
                console.error('Initial account expiry check failed:', err);
            });
            setInterval(() => {
                billing.expireOverdueAccounts().catch((err) => {
                    console.error('Periodic account expiry check failed:', err);
                });
            }, EXPIRY_CHECK_INTERVAL_MS);
        });
    })
    .catch((err) => {
        console.error('FATAL: database schema not ready; refusing to start server:', err.message);
        process.exit(1);
    });
