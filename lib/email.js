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

    // Shared email shell: outer wrapper + brand header + body slot + footer.
    // `innerHtml` is the <tr>…</tr> rows that go inside the white card (the
    // body cell). Both the CTA email (buildEmailHtml) and the notification
    // email (buildNotificationEmailHtml) render through this so the brand
    // chrome never diverges.
    function renderShell(innerHtml) {
        const baseUrl = getPortalBaseUrl();
        const logoUrl = `${baseUrl}/logo-white.png`;
        const portalUrl = baseUrl;
        const year = new Date().getFullYear();

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
            '        <td style="background: linear-gradient(135deg, #1d4ed8 0%, #1e3a8a 100%); padding: 32px; text-align: center;">',
            `          <img src="${logoUrl}" alt="Apex Infosys" height="48" style="display: block; margin: 0 auto; width: auto;">`,
            '        </td>',
            '      </tr>',
            '',
            innerHtml,
            '',
            '    </table>',
            '    <!-- /Card -->',
            '',
            '    <!-- Footer -->',
            '    <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width: 560px; width: 100%;">',
            '      <tr>',
            '        <td style="padding: 24px 32px; text-align: center; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
            `          <p style="margin: 0 0 10px; font-size: 12px; color: #94a3b8;"><a href="${portalUrl}" style="color: #64748b; text-decoration: none;">Oasis Cloud</a> &mdash; Secure remote access for your smart home</p>`,
            '          <p style="margin: 0 0 10px; font-size: 11px; line-height: 1.5; color: #cbd5e1;">Please do not reply to this email. Emails sent to this address will not be answered.</p>',
            `          <p style="margin: 0; font-size: 11px; line-height: 1.5; color: #cbd5e1;">Copyright &copy; ${year} AII IoTech (India) Private Limited, dba APEX. All rights reserved.</p>`,
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

    // Build the inner card body shared between both templates: a heading + body
    // paragraph, an OPTIONAL CTA button (only when ctaUrl+ctaLabel are given),
    // an OPTIONAL expiry line (only when expiryHours is given), and a footnote.
    function renderCardBody({ heading, body, ctaUrl, ctaLabel, expiryHours, footnote }) {
        const rows = [
            '      <!-- Body -->',
            '      <tr>',
            '        <td style="padding: 36px 32px 12px; font-family: Inter, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; color: #0f172a;">',
            `          <h1 style="margin: 0 0 16px; font-size: 22px; font-weight: 700; color: #0f172a; letter-spacing: -0.01em;">${heading}</h1>`,
            `          <p style="margin: 0 0 28px; font-size: 15px; line-height: 1.6; color: #475569;">${body}</p>`
        ];

        if (ctaUrl && ctaLabel) {
            rows.push(
                '',
                '          <!-- CTA button -->',
                '          <table role="presentation" cellpadding="0" cellspacing="0" style="margin: 0 0 28px;">',
                '            <tr>',
                '              <td style="background: #1d4ed8; border-radius: 8px;">',
                `                <a href="${ctaUrl}" target="_blank" style="display: inline-block; padding: 14px 32px; font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 15px; font-weight: 600; color: #ffffff; text-decoration: none;">${ctaLabel}</a>`,
                '              </td>',
                '            </tr>',
                '          </table>'
            );
        }

        if (expiryHours && ctaUrl) {
            rows.push(
                '',
                `          <p style="margin: 0 0 8px; font-size: 13px; line-height: 1.5; color: #64748b;">This link expires in ${expiryHours} hour(s). If the button doesn't work, copy and paste this URL into your browser:</p>`,
                `          <p style="margin: 0 0 0; font-size: 12px; line-height: 1.5; color: #94a3b8; word-break: break-all;">${ctaUrl}</p>`
            );
        }

        rows.push(
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
            '      </tr>'
        );

        return rows.join('\n');
    }

    // Action email (verify, reset): always has a CTA button + expiry line.
    function buildEmailHtml({ heading, body, ctaUrl, ctaLabel, expiryHours, footnote }) {
        return renderShell(renderCardBody({ heading, body, ctaUrl, ctaLabel, expiryHours, footnote }));
    }

    // Security notification email (passkey added/removed, password changed,
    // account deleted): no expiry line; CTA button optional.
    function buildNotificationEmailHtml({ heading, body, footnote, ctaUrl, ctaLabel }) {
        return renderShell(renderCardBody({ heading, body, ctaUrl, ctaLabel, footnote }));
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
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
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
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
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

    // ── Security-event notifications (best-effort, never throw) ─────────────
    // Every notification sender funnels through here: a no-op when email is
    // unconfigured, and it swallows + logs send failures so a notification can
    // never block or fail the security action that triggered it.
    async function notifySecurityEvent({ to, subject, text, html }) {
        if (!isEmailConfigured()) {
            return;
        }
        try {
            await getResendClient().emails.send({
                from: `${config.RESEND_FROM_NAME} <${config.RESEND_FROM_EMAIL}>`,
                to: [to],
                subject,
                text,
                html
            });
        } catch (err) {
            console.error('[email] security notify failed:', subject, err?.message || err);
        }
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Human, locale-stable timestamp for the email body (UTC to avoid surprises).
    function formatEventTime(when) {
        const d = when instanceof Date ? when : new Date();
        return d.toUTCString();
    }

    function sendPasskeyAddedEmail(userEmail, { nickname, when } = {}) {
        const which = nickname ? `"${nickname}"` : 'a new passkey';
        const whichHtml = nickname ? `&ldquo;${escapeHtml(nickname)}&rdquo;` : 'a new passkey';
        const ts = formatEventTime(when);
        return notifySecurityEvent({
            to: userEmail,
            subject: 'A new passkey was added to your Oasis account',
            text: [
                'A new passkey was just added to your Oasis Cloud account.',
                '',
                `Passkey: ${which}`,
                `When: ${ts}`,
                '',
                "If you added this, no action is needed. If you didn't, reset your password immediately and contact support.",
                '',
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
            ].join('\n'),
            html: buildNotificationEmailHtml({
                heading: 'A new passkey was added',
                body: `A new passkey (${whichHtml}) was just added to your Oasis Cloud account on <strong>${escapeHtml(ts)}</strong>.`,
                footnote:
                    "If you added this, no action is needed. If you didn't, reset your password immediately from the sign-in page and contact support."
            })
        });
    }

    function sendPasskeyRemovedEmail(userEmail, { nickname, when } = {}) {
        const which = nickname ? `"${nickname}"` : 'a passkey';
        const whichHtml = nickname ? `&ldquo;${escapeHtml(nickname)}&rdquo;` : 'a passkey';
        const ts = formatEventTime(when);
        return notifySecurityEvent({
            to: userEmail,
            subject: 'A passkey was removed from your Oasis account',
            text: [
                'A passkey was just removed from your Oasis Cloud account.',
                '',
                `Passkey: ${which}`,
                `When: ${ts}`,
                '',
                "If you removed this, no action is needed. If you didn't, reset your password immediately and contact support.",
                '',
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
            ].join('\n'),
            html: buildNotificationEmailHtml({
                heading: 'A passkey was removed',
                body: `${whichHtml.charAt(0).toUpperCase() + whichHtml.slice(1)} was just removed from your Oasis Cloud account on <strong>${escapeHtml(ts)}</strong>.`,
                footnote:
                    "If you removed this, no action is needed. If you didn't, reset your password immediately from the sign-in page and contact support."
            })
        });
    }

    function sendPasswordChangedEmail(userEmail) {
        const ts = formatEventTime(new Date());
        const loginUrl = `${getPortalBaseUrl()}/login.html`;
        return notifySecurityEvent({
            to: userEmail,
            subject: 'Your Oasis password was changed',
            text: [
                'The password for your Oasis Cloud account was just changed.',
                '',
                `When: ${ts}`,
                '',
                "If you made this change, no action is needed. If you didn't, reset your password immediately using the 'Forgot your password?' link on the sign-in page and contact support.",
                '',
                loginUrl,
                '',
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
            ].join('\n'),
            html: buildNotificationEmailHtml({
                heading: 'Your password was changed',
                body: `The password for your Oasis Cloud account was just changed on <strong>${escapeHtml(ts)}</strong>. If you made this change, you can ignore this email.`,
                ctaUrl: loginUrl,
                ctaLabel: 'Go to sign-in',
                footnote:
                    "If you didn't change your password, reset it immediately using the &ldquo;Forgot your password?&rdquo; link on the sign-in page and contact support."
            })
        });
    }

    function sendAccountDeletedEmail(userEmail) {
        const ts = formatEventTime(new Date());
        return notifySecurityEvent({
            to: userEmail,
            subject: 'Your Oasis account has been deleted',
            text: [
                'Your Oasis Cloud account, all of its devices, and any active subscription have been permanently deleted.',
                '',
                `When: ${ts}`,
                '',
                "If you requested this, no action is needed. If you didn't, contact support immediately.",
                '',
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
            ].join('\n'),
            html: buildNotificationEmailHtml({
                heading: 'Your account has been deleted',
                body: `Your Oasis Cloud account, all of its devices, and any active subscription were permanently deleted on <strong>${escapeHtml(ts)}</strong>. This cannot be undone.`,
                footnote: "If you didn't request this deletion, contact support immediately."
            })
        });
    }

    function sendSessionsRevokedEmail(userEmail) {
        const ts = formatEventTime(new Date());
        const loginUrl = `${getPortalBaseUrl()}/login.html`;
        return notifySecurityEvent({
            to: userEmail,
            subject: 'You were signed out of all devices on your Oasis account',
            text: [
                'Your Oasis Cloud account was just signed out everywhere.',
                '',
                `When: ${ts}`,
                '',
                'This signs out Apex MCU Plus, Google Home, Alexa, and all browsers. Devices must re-register and integrations must be re-linked.',
                '',
                "If you did this, no action is needed. If you didn't, reset your password immediately and contact support.",
                '',
                loginUrl,
                '',
                'Oasis Cloud - Secure remote access for your smart home',
                '',
                'Please do not reply to this email. Emails sent to this address will not be answered.',
                `Copyright (c) ${new Date().getFullYear()} AII IoTech (India) Private Limited, dba APEX. All rights reserved.`
            ].join('\n'),
            html: buildNotificationEmailHtml({
                heading: 'You were signed out of all devices',
                body: `Your Oasis Cloud account was signed out everywhere on <strong>${escapeHtml(ts)}</strong>. This includes Apex MCU Plus, Google Home, Alexa, and all browsers &mdash; devices must re-register and integrations must be re-linked.`,
                ctaUrl: loginUrl,
                ctaLabel: 'Go to sign-in',
                footnote:
                    "If you did this, no action is needed. If you didn't, reset your password immediately from the sign-in page and contact support."
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
        sendPasswordResetEmail,
        sendPasskeyAddedEmail,
        sendPasskeyRemovedEmail,
        sendPasswordChangedEmail,
        sendAccountDeletedEmail,
        sendSessionsRevokedEmail
    };
};
