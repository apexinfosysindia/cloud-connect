const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');

module.exports = function ({ dbAll, dbGet, utils, auth, billing }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.post(
        '/api/admin/login',
        asyncHandler(async (req, res) => {
            const { email, password } = req.body;

            try {
                auth.ensureAdminConfigured();
            } catch (error) {
                return res.status(500).json({ error: error.message });
            }

            if (email !== process.env.ADMIN_EMAIL) {
                return res.status(401).json({ error: 'Invalid admin credentials' });
            }

            const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
            let passwordValid = false;

            if (adminPasswordHash) {
                passwordValid = await bcrypt.compare(password, adminPasswordHash);
            } else if (process.env.ADMIN_PASSWORD) {
                const expectedBuffer = Buffer.from(process.env.ADMIN_PASSWORD);
                const receivedBuffer = Buffer.from(password || '');
                passwordValid =
                    expectedBuffer.length === receivedBuffer.length &&
                    crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
            }

            if (!passwordValid) {
                return res.status(401).json({ error: 'Invalid admin credentials' });
            }

            res.status(200).json({
                message: 'Admin login successful',
                email,
                token: auth.createAdminToken(email)
            });
        })
    );

    router.get('/api/admin/me', auth.requireAdmin, (req, res) => {
        res.status(200).json({
            email: req.admin.email
        });
    });

    router.get(
        '/api/admin/users',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const rows = await dbAll(`
            SELECT *
            FROM users
            ORDER BY
                CASE status
                    WHEN 'payment_pending' THEN 0
                    WHEN 'trial' THEN 1
                    WHEN 'active' THEN 2
                    WHEN 'suspended' THEN 3
                    WHEN 'expired' THEN 4
                    ELSE 5
                END,
                created_at DESC
        `);

            res.status(200).json({
                users: rows.map(auth.serializeAdminUser)
            });
        })
    );

    router.post(
        '/api/admin/users/:id/status',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const { id } = req.params;
            const { status, trial_days } = req.body;
            const allowedStatuses = ['active', 'trial', 'suspended'];

            if (!allowedStatuses.includes(status)) {
                return res.status(400).json({ error: 'Invalid status' });
            }

            // Suspend = stop billing AND lock out locally. If the user has a
            // live Razorpay subscription we cancel it first (at cycle end so
            // paid users keep access until period end; trial users get
            // trial-aborted immediately inside cancelSubscription). Best
            // effort: if the Razorpay call fails we still proceed with the
            // local suspend so admins aren't blocked by Razorpay outages,
            // but we report the cancel error back in the response.
            let cancelResult = null;
            let cancelError = null;
            if (status === 'suspended') {
                const existing = await dbGet(`SELECT * FROM users WHERE id = ?`, [Number(id)]);
                if (!existing) {
                    return res.status(404).json({ error: 'User not found' });
                }
                const rzpStatus = String(existing.razorpay_subscription_status || '').toLowerCase();
                const terminal = ['cancelled', 'completed', 'expired', 'halted'].includes(rzpStatus);
                if (existing.razorpay_subscription_id && !terminal) {
                    try {
                        cancelResult = await billing.cancelSubscription(Number(id), { atCycleEnd: true });
                    } catch (error) {
                        console.error(
                            `Admin suspend: Razorpay cancel failed for ${existing.email}:`,
                            error.message
                        );
                        cancelError = error.message || 'Unable to cancel subscription on Razorpay.';
                    }
                }
            }

            const updatedUser = await billing.updateUserStatus(Number(id), status, {
                trialDays: Number(trial_days) || 365
            });

            if (!updatedUser) {
                return res.status(404).json({ error: 'User not found' });
            }

            let message = 'User status updated';
            if (status === 'suspended') {
                if (cancelError) {
                    message = `Account suspended locally, but Razorpay subscription cancel failed: ${cancelError}. Please reconcile manually.`;
                } else if (cancelResult?.trialAbort) {
                    message = `Account suspended and Razorpay trial cancelled. User moved to payment_pending.`;
                } else if (cancelResult?.atCycleEnd) {
                    message = `Account suspended. Razorpay subscription cancelled at cycle end.`;
                } else if (cancelResult?.cancelled) {
                    message = `Account suspended and Razorpay subscription cancelled (no billing cycle had started).`;
                }
            }

            res.status(200).json({
                message,
                user: auth.serializeAdminUser(updatedUser)
            });
        })
    );

    router.delete(
        '/api/admin/users/:id',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            const { id } = req.params;

            const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [Number(id)]);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            const deleted = await billing.deleteUserAccount(Number(id));
            if (!deleted) {
                return res.status(500).json({ error: 'Unable to delete user' });
            }

            res.status(200).json({
                message: `Account ${deleted.email} has been permanently deleted.`
            });
        })
    );

    return router;
};
