const path = require('path');
const express = require('express');

module.exports = function ({ config }) {
    const router = express.Router();

    router.get(['/login', '/login.html', '/signup', '/signup.html'], (req, res, next) => {
        const isSignupPath = req.path.startsWith('/signup');
        const targetPath = isSignupPath ? '/signup.html' : '/login.html';
        const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';

        if (req.hostname === config.CUSTOMER_PORTAL_HOST) {
            if (req.path === '/login' || req.path === '/signup') {
                return res.redirect(`${targetPath}${query}`);
            }
            return next();
        }

        if (req.hostname === config.ADMIN_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.CUSTOMER_PORTAL_HOST}${targetPath}${query}`);
        }

        return next();
    });

    router.get(['/admin', '/admin.html'], (req, res, next) => {
        if (req.hostname === config.ADMIN_PORTAL_HOST) {
            return res.redirect('/');
        }

        if (req.hostname === config.CUSTOMER_PORTAL_HOST || req.hostname === config.CLOUD_BASE_DOMAIN) {
            return res.redirect(`https://${config.ADMIN_PORTAL_HOST}/`);
        }

        return next();
    });

    router.get('/index.html', (req, res) => {
        if (req.hostname === config.ADMIN_PORTAL_HOST || req.hostname === config.CUSTOMER_PORTAL_HOST) {
            return res.redirect('/');
        }

        return res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
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
