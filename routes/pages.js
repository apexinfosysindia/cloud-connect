const path = require('path');
const express = require('express');

// Page routing + canonical host enforcement.
//
// URLs are extensionless everywhere (.html is hidden): a global middleware in
// server.js 301s any /*.html → its clean path before this router runs, and
// express.static is configured with extensions:['html'] so /login resolves to
// login.html on disk. This router only has to (a) keep each portal page on its
// correct host (redirecting cross-host hits to oasis/vista), and (b) serve the
// host-specific landing/admin/login page at `/`. All redirect targets below are
// extensionless so the address bar never shows .html.
module.exports = function ({ config }) {
    const router = express.Router();

    // HTML pages are served via res.sendFile (which the express.static
    // setHeaders does NOT cover), so force revalidation here too — otherwise a
    // soft refresh can keep serving a stale page shell.
    router.use((req, res, next) => {
        res.set('Cache-Control', 'no-cache');
        next();
    });

    // Carry any querystring (?token=…, ?google_oauth=1, …) across a cross-host
    // redirect so verify/reset/OAuth links keep working when hit on the wrong host.
    const queryOf = (req) => {
        const i = req.originalUrl.indexOf('?');
        return i >= 0 ? req.originalUrl.slice(i) : '';
    };

    // Customer (Oasis) auth pages: login + signup.
    router.get(['/login', '/signup'], (req, res, next) => {
        if (req.hostname === config.CUSTOMER_PORTAL_HOST) {
            return next();
        }
        if (req.hostname === config.ADMIN_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${req.path}${queryOf(req)}`);
        }
        return next();
    });

    // Customer (Oasis) account-lifecycle pages: email verification + password reset.
    router.get(['/verify-email', '/reset-password'], (req, res, next) => {
        if (req.hostname === config.CUSTOMER_PORTAL_HOST) {
            return next();
        }
        if (req.hostname === config.ADMIN_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${req.path}${queryOf(req)}`);
        }
        return next();
    });

    // Admin (Vista) dashboard.
    router.get('/admin', (req, res, next) => {
        if (req.hostname === config.ADMIN_PORTAL_HOST) {
            return res.redirect('/');
        }
        if (req.hostname === config.CUSTOMER_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.ADMIN_PORTAL_HOST}/`);
        }
        return next();
    });

    // Admin security page (passkeys + credentials). Served only on the admin
    // host; other hosts are redirected to the admin portal. No nav link — admins
    // reach it by URL — and the page itself requires sudo re-auth before showing
    // any control.
    router.get('/admin-security', (req, res, next) => {
        if (req.hostname === config.ADMIN_PORTAL_HOST) {
            return res.sendFile(path.join(__dirname, '..', 'public', 'admin-security.html'));
        }
        if (req.hostname === config.CUSTOMER_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.ADMIN_PORTAL_HOST}/admin-security`);
        }
        return next();
    });

    router.get('/', (req, res) => {
        if (req.hostname === config.ADMIN_PORTAL_HOST) {
            return res.sendFile(path.join(__dirname, '..', 'public', 'admin.html'));
        }

        if (req.hostname === config.CUSTOMER_PORTAL_HOST) {
            return res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
        }

        return res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
    });

    return router;
};
