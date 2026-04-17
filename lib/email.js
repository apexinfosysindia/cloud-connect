const crypto = require('crypto');
const { Resend } = require('resend');

module.exports = function ({ dbGet, dbRun, config, utils }) {
    let resendClient = null;

    function isEmailConfigured() {
        return Boolean(config.RESEND_API_KEY);
    }

    function getResendClient() {
        if (resendClient) {
            return resendClient;
        }

        if (!isEmailConfigured()) {
            throw new Error('Resend email is not configured. Set RESEND_API_KEY in .env');
        }

        resendClient = new Resend(config.RESEND_API_KEY);
        return resendClient;
    }

    function generateEmailToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    function getPortalBaseUrl() {
        const protocol = config.PORTAL_SESSION_COOKIE_SECURE ? 'https' : 'http';
        return `${protocol}://${config.CUSTOMER_PORTAL_HOST}`;
    }

    async function createEmailVerificationToken(userId) {
        // Invalidate any existing unused tokens for this user
        await dbRun(
            `UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL`,
            [userId]
        );

        const token = generateEmailToken();
        const tokenHash = utils.hashSecret(token);
        const expiresAt = new Date(Date.now() + config.EMAIL_VERIFICATION_TOKEN_TTL_MS).toISOString();

        await dbRun(
            `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
            [userId, tokenHash, expiresAt]
        );

        return token;
    }

    async function verifyEmailToken(token) {
        const tokenHash = utils.hashSecret(token);
        const row = await dbGet(
            `SELECT evt.*, u.email FROM email_verification_tokens evt
             JOIN users u ON u.id = evt.user_id
             WHERE evt.token_hash = ? AND evt.used_at IS NULL AND evt.expires_at > datetime('now')`,
            [tokenHash]
        );

        return row || null;
    }

    async function markEmailVerificationTokenUsed(tokenId) {
        await dbRun(
            `UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`,
            [tokenId]
        );
    }

    async function markUserEmailVerified(userId) {
        await dbRun(
            `UPDATE users SET email_verified = 1 WHERE id = ?`,
            [userId]
        );
    }

    async function createPasswordResetToken(userId) {
        // Invalidate any existing unused tokens for this user
        await dbRun(
            `UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND used_at IS NULL`,
            [userId]
        );

        const token = generateEmailToken();
        const tokenHash = utils.hashSecret(token);
        const expiresAt = new Date(Date.now() + config.PASSWORD_RESET_TOKEN_TTL_MS).toISOString();

        await dbRun(
            `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)`,
            [userId, tokenHash, expiresAt]
        );

        return token;
    }

    async function verifyPasswordResetToken(token) {
        const tokenHash = utils.hashSecret(token);
        const row = await dbGet(
            `SELECT prt.*, u.email FROM password_reset_tokens prt
             JOIN users u ON u.id = prt.user_id
             WHERE prt.token_hash = ? AND prt.used_at IS NULL AND prt.expires_at > datetime('now')`,
            [tokenHash]
        );

        return row || null;
    }

    async function markPasswordResetTokenUsed(tokenId) {
        await dbRun(
            `UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`,
            [tokenId]
        );
    }

    function buildEmailHtml({ heading, body, ctaUrl, ctaLabel, expiryHours, footnote }) {
        const baseUrl = getPortalBaseUrl();
        const logoUrl = `${baseUrl}/logo-white.png`;
        const portalUrl = baseUrl;

        return [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>',
            '<body style="margin: 0; padding: 0; background-color: #eef2f6; -webkit-font-smoothing: antialiased;">',
            '',
            '<!-- Outer wrapper -->',
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #eef2f6;">',
            '  <tr><td align="center" style="padding: 40px 16px;">',
            '',
            '    <!-- Card -->',
            '    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width: 560px; width: 100%; background-color: #ffffff; border-radius: 16px; box-shadow: 0 8px 20px rgba(15, 23, 42, 0.05); overflow: hidden;">',
            '',
            '      <!-- Brand header -->',
            '      <tr>',
            '        <td style="background: linear-gradient(135deg, #1d4ed8 0%, #1e3a8a 100%); padding: 28px 32px; text-align: center;">',
            `          <img src="${logoUrl}" alt="Apex Infosys" width="120" style="display: inline-block; vertical-align: middle; margin-right: 14px; height: auto;">`,
            '          <span style="display: inline-block; vertical-align: middle; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; font-size: 20px; font-weight: 700; color: #ffffff; letter-spacing: -0.02em;">Oasis Cloud</span>',
            '        </td>',
            '      </tr>',
            '',
            '      <!-- Body -->',
            '      <tr>',
            '        <td style="padding: 36px 32px 12px; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; color: #0f172a;">',
            `          <h1 style="margin: 0 0 16px; font-size: 22px; font-weight: 700; color: #0f172a; letter-spacing: -0.01em;">${heading}</h1>`,
            `          <p style="margin: 0 0 28px; font-size: 15px; line-height: 1.6; color: #475569;">${body}</p>`,
            '',
            '          <!-- CTA button -->',
            '          <table role="presentation" cellpadding="0" cellspacing="0" style="margin: 0 0 28px;">',
            '            <tr>',
            `              <td style="background: #1d4ed8; border-radius: 8px;">`,
            `                <a href="${ctaUrl}" target="_blank" style="display: inline-block; padding: 14px 32px; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; font-size: 15px; font-weight: 600; color: #ffffff; text-decoration: none;">${ctaLabel}</a>`,
            '              </td>',
            '            </tr>',
            '          </table>',
            '',
            `          <p style="margin: 0 0 8px; font-size: 13px; line-height: 1.5; color: #64748b;">This link expires in ${expiryHours} hour(s). If the button doesn't work, copy and paste this URL into your browser:</p>`,
            `          <p style="margin: 0 0 0; font-size: 12px; line-height: 1.5; color: #94a3b8; word-break: break-all;">${ctaUrl}</p>`,
            '        </td>',
            '      </tr>',
            '',
            '      <!-- Divider -->',
            '      <tr>',
            '        <td style="padding: 0 32px;">',
            '          <div style="border-top: 1px solid #e2e8f0; margin: 24px 0;"></div>',
            '        </td>',
            '      </tr>',
            '',
            '      <!-- Footnote -->',
            '      <tr>',
            '        <td style="padding: 0 32px 32px; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
            `          <p style="margin: 0; font-size: 12px; line-height: 1.5; color: #94a3b8;">${footnote}</p>`,
            '        </td>',
            '      </tr>',
            '',
            '    </table>',
            '    <!-- /Card -->',
            '',
            '    <!-- Footer -->',
            '    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width: 560px; width: 100%;">',
            '      <tr>',
            '        <td style="padding: 24px 32px; text-align: center; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
            `          <p style="margin: 0 0 4px; font-size: 12px; color: #94a3b8;"><a href="${portalUrl}" style="color: #64748b; text-decoration: none;">Apex Infosys India</a></p>`,
            '          <p style="margin: 0; font-size: 11px; color: #cbd5e1;">Oasis Cloud &mdash; Secure remote access for your smart home</p>',
            '        </td>',
            '      </tr>',
            '    </table>',
            '',
            '  </td></tr>',
            '</table>',
            '',
            '</body>',
            '</html>'
        ].join('\n');
    }

    async function sendVerificationEmail(userEmail, token) {
        const baseUrl = getPortalBaseUrl();
        const verifyUrl = `${baseUrl}/verify-email.html?token=${encodeURIComponent(token)}`;

        const expiryHours = Math.round(config.EMAIL_VERIFICATION_TOKEN_TTL_MS / (60 * 60 * 1000));

        await getResendClient().emails.send({
            from: `${config.RESEND_FROM_NAME} <${config.RESEND_FROM_EMAIL}>`,
            to: [userEmail],
            subject: 'Verify your Oasis Cloud account',
            text: [
                'Welcome to Oasis Cloud by Apex Infosys!',
                '',
                'Please verify your email address by clicking the link below:',
                '',
                verifyUrl,
                '',
                `This link expires in ${expiryHours} hour(s).`,
                '',
                'If you did not create an account, you can safely ignore this email.',
                '',
                'Apex Infosys India',
                'Oasis Cloud - Secure remote access for your smart home'
            ].join('\n'),
            html: buildEmailHtml({
                heading: 'Verify your email address',
                body: 'Welcome to Oasis Cloud! Please verify your email address to continue setting up your account.',
                ctaUrl: verifyUrl,
                ctaLabel: 'Verify Email Address',
                expiryHours,
                footnote: 'If you did not create an account, you can safely ignore this email.'
            })
        });
    }

    async function sendPasswordResetEmail(userEmail, token) {
        const baseUrl = getPortalBaseUrl();
        const resetUrl = `${baseUrl}/reset-password.html?token=${encodeURIComponent(token)}`;

        const expiryHours = Math.round(config.PASSWORD_RESET_TOKEN_TTL_MS / (60 * 60 * 1000));

        await getResendClient().emails.send({
            from: `${config.RESEND_FROM_NAME} <${config.RESEND_FROM_EMAIL}>`,
            to: [userEmail],
            subject: 'Reset your Oasis Cloud password',
            text: [
                'Oasis Cloud by Apex Infosys - Password Reset',
                '',
                'A password reset was requested for your account. Click the link below to set a new password:',
                '',
                resetUrl,
                '',
                `This link expires in ${expiryHours} hour(s).`,
                '',
                'If you did not request this, you can safely ignore this email. Your password will not change.',
                '',
                'Apex Infosys India',
                'Oasis Cloud - Secure remote access for your smart home'
            ].join('\n'),
            html: buildEmailHtml({
                heading: 'Reset your password',
                body: 'A password reset was requested for your Oasis Cloud account. Click the button below to set a new password.',
                ctaUrl: resetUrl,
                ctaLabel: 'Reset Password',
                expiryHours,
                footnote: 'If you did not request a password reset, you can safely ignore this email. Your password will not change.'
            })
        });
    }

    return {
        isEmailConfigured,
        generateEmailToken,
        createEmailVerificationToken,
        verifyEmailToken,
        markEmailVerificationTokenUsed,
        markUserEmailVerified,
        createPasswordResetToken,
        verifyPasswordResetToken,
        markPasswordResetTokenUsed,
        sendVerificationEmail,
        sendPasswordResetEmail
    };
};
