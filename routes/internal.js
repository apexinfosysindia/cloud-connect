const express = require('express');

module.exports = function ({ dbGet, config, utils }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.get(
        '/api/internal/verify-domain',
        asyncHandler(async (req, res) => {
            const { domain } = req.query;
            if (!domain) {
                return res.status(400).send('Domain missing');
            }

            const baseDomain = `.${config.CLOUD_BASE_DOMAIN}`;
            if (!domain.endsWith(baseDomain)) {
                return res.status(403).send('Not our domain');
            }

            const subdomain = domain.replace(baseDomain, '');
            const row = await dbGet(`SELECT status FROM users WHERE subdomain = ?`, [subdomain]);

            if (!row) {
                return res.status(403).send('Domain not found');
            }

            if (utils.isAccessEnabled(row.status)) {
                return res.status(200).send('OK');
            }

            return res.status(403).send('Subscription Expired/Suspended');
        })
    );

    router.post('/api/internal/verify-token', async (req, res) => {
        let body = req.body;
        if (body.content === undefined && Object.keys(body).length > 0) {
            try {
                if (typeof req.body === 'string') {
                    body = JSON.parse(req.body);
                }
            } catch (_error) {
                // Ignore parse fallback failures and use the original body.
            }
        }

        const op = body.op;
        const content = body.content || body;

        const reject = (reason) => res.status(200).json({ reject: true, reject_reason: reason });
        const accept = () => res.status(200).json({ reject: false, unchange: true });

        const opsRequiringTokenValidation = new Set(['Login', 'Ping', 'NewWorkConn', 'NewUserConn']);
        if (!opsRequiringTokenValidation.has(op)) {
            return accept();
        }

        const tokenCandidates = [
            content?.metas?.token,
            content?.user?.metas?.token,
            content?.meta?.token,
            content?.user?.meta?.token,
            content?.client_token,
            typeof content?.user === 'string' ? content.user : null,
            content?.token,
            content?.metadatas?.token,
            content?.custom_dict?.token,
            content?.run_id
        ];

        const token = tokenCandidates.find((candidate) => typeof candidate === 'string' && candidate.length > 0);

        if (!token) {
            console.error('Token not found in payload:', JSON.stringify(content, null, 2));
            return reject('Missing Access Token. Received content keys: ' + Object.keys(content || {}).join(', '));
        }

        try {
            const row = await dbGet(`SELECT status FROM users WHERE access_token = ?`, [token]);
            if (!row) {
                return reject('Invalid Token');
            }

            if (utils.isAccessEnabled(row.status)) {
                return accept();
            }

            return reject('Account not active');
        } catch (error) {
            console.error('VERIFY TOKEN ERROR:', error);
            return reject('Internal verification error');
        }
    });

    return router;
};
