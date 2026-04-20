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

// Alexa modules (same shape as the Google stack; share users + entities tables)
const alexaState = require('./lib/alexa/state');
const alexaDirectiveMapping = require('./lib/alexa/directive-mapping');
const alexaCore = require('./lib/alexa/core')({ dbGet, dbRun });
const alexaEvents = require('./lib/alexa/events')({
    dbGet,
    dbRun,
    dbAll,
    config,
    utils,
    state: alexaState,
    directiveMapping: alexaDirectiveMapping
});

// Auth depends on device and googleCore, so it must be initialized after them
const auth = require('./lib/auth')({ dbGet, config, utils, device, googleCore, alexaCore });

// Email module for verification and password reset flows
const email = require('./lib/email')({ dbGet, dbRun, config, utils });

// --- Express app setup ---
const app = express();

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
    max: 100, // 100 requests per minute per IP
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
app.use('/api/auth/login', authRateLimiter);
app.use('/api/admin/login', authRateLimiter);
app.use('/api/auth/signup', signupRateLimiter);
app.use('/api/auth/forgot-password', emailRateLimiter);
app.use('/api/auth/resend-verification', emailRateLimiter);
app.use('/api/auth/reset-password', authRateLimiter);
app.use('/api/auth/verify-email', authRateLimiter);

// Password-gated account-management endpoints. These all bcrypt.compare()
// against the user's password, so they're brute-force targets for anyone
// who hijacks a portal session token. Hold them under the strict auth
// limiter rather than the relaxed 100/min general API bucket.
app.use('/api/account/change-password', authRateLimiter);
app.use('/api/account/delete', authRateLimiter);
app.use('/api/account/cancel-subscription', authRateLimiter);

// --- Static files ---
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// --- Shared deps object for route factories ---
const deps = {
    dbGet,
    dbRun,
    dbAll,
    dbTransaction,
    config,
    utils,
    auth,
    email,
    device,
    billing,
    googleCore,
    homegraph,
    entityMapping,
    state,
    alexaCore,
    alexaEvents,
    alexaDirectiveMapping,
    alexaState
};

// --- Register routes ---
app.use(require('./routes/pages')(deps));
app.use(require('./routes/device-api')(deps));
app.use(require('./routes/admin-fleet')(deps));
app.use(require('./routes/auth')(deps));
app.use(require('./routes/billing')(deps));
app.use(require('./routes/admin')(deps));
app.use(require('./routes/internal')(deps));
app.use(require('./routes/google-home-portal')(deps));
app.use(require('./routes/google-home-oauth')(deps));
app.use(require('./routes/google-home-fulfillment')(deps));
app.use(require('./routes/google-home-device-api')(deps));
app.use(require('./routes/google-home-admin')(deps));
app.use(require('./routes/alexa-portal')(deps));
app.use(require('./routes/alexa-oauth')(deps));
app.use(require('./routes/alexa-fulfillment')(deps));

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
            alexaCore
                .ensureAlexaRuntimeSchemaReady()
                .then(() => {
                    console.log('Alexa runtime schema ready.');
                })
                .catch((error) => {
                    console.error('Alexa runtime schema migration failed:', error);
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
