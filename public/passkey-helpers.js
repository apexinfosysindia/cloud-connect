/**
 * Shared passkey UI helpers — loaded by login.html, signup.html, admin.html and
 * admin-security.html (before account.js / the inline scripts). Exposed on
 * window.PasskeyHelpers so both the account.js IIFE and the admin inline scripts
 * destructure ONE copy instead of hand-maintaining three (the drift between
 * those copies is what let an admin-login hang bug slip through earlier).
 *
 * Pure utilities — no page state, safe to share across all four pages.
 */
(function () {
    // Race a promise against a timeout so a WebAuthn ceremony that never settles
    // (iOS Safari can absorb a non-Apple authenticator flow, leaving
    // navigator.credentials.{create,get}() hanging forever) can't leave the UI
    // stuck on "Waiting for passkey...". startAuthentication/startRegistration@9
    // have no abort param, so this only stops OUR await; a late ceremony is
    // harmless.
    function withTimeout(promise, ms, name = 'PasskeyTimeoutError') {
        let t;
        const timer = new Promise((_resolve, reject) => {
            t = setTimeout(() => {
                const e = new Error('Passkey ceremony timed out');
                e.name = name;
                reject(e);
            }, ms);
        });
        return Promise.race([promise, timer]).finally(() => clearTimeout(t));
    }

    // Translate a WebAuthn DOMException into a human message + flags. Note:
    // InvalidStateError is success-adjacent — it means a passkey ALREADY exists
    // on this authenticator (the browser refusing a duplicate), so it is shown
    // as informational (isError:false), not a red failure.
    function describePasskeyError(err) {
        const name = (err && err.name) || '';
        // For DOMExceptions the diagnostic is the name; for a plain Error
        // (e.g. a server verify error) the message is the meaningful part.
        const isDomException = typeof DOMException !== 'undefined' && err instanceof DOMException;
        const detail = isDomException ? name : (err && err.message) || name || 'Unknown error';
        if (name === 'PasskeyTimeoutError') {
            return {
                isError: true,
                message:
                    "Passkey setup didn't complete. On iPhone, try choosing iCloud Keychain instead of a third-party app, or try a different device."
            };
        }
        switch (name) {
            case 'NotAllowedError':
            case 'AbortError':
                return { isError: false, message: 'Passkey setup was cancelled.' };
            case 'InvalidStateError':
                return {
                    isError: false,
                    message:
                        'You already have a passkey set up on this device. You can use it to sign in, or remove it first to register a new one.'
                };
            case 'NotSupportedError':
                return { isError: true, message: "This device or browser doesn't support passkeys." };
            case 'SecurityError':
                return { isError: true, message: "Couldn't add passkey due to a security/origin error." };
            default:
                return { isError: true, message: `Couldn't add passkey (${detail}).` };
        }
    }

    // Build a human, distinguishable default passkey name from signals available
    // at enroll time: "<Browser> on <OS> · <method>". The method comes from the
    // new credential's transports (internal = platform / Touch ID / Windows
    // Hello, hybrid = phone, usb/nfc/ble = security key), so multiple keys
    // enrolled from one device via different authenticators don't collide. (The
    // server prefers an AAGUID-resolved provider name over this when available.)
    function describePasskeyDevice(attestation) {
        let os = '';
        let browser = '';
        const uaData = navigator.userAgentData;
        if (uaData && Array.isArray(uaData.brands)) {
            os = uaData.platform || '';
            // brands lists BOTH "Chromium" and the real brand (e.g. "Google
            // Chrome", "Brave", "Microsoft Edge"). Prefer the specific brand
            // over the generic "Chromium" so names read "Chrome", not "Chromium".
            const real = uaData.brands.map((b) => b.brand).filter((b) => b && !/Not.?A.?Brand/i.test(b));
            browser = real.find((b) => !/chromium/i.test(b)) || real[0] || '';
            browser = browser.replace(/^Google\s+/i, '').replace(/^Microsoft\s+/i, '');
        }
        const ua = navigator.userAgent || '';
        if (!os) {
            if (/Windows/i.test(ua)) os = 'Windows';
            else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
            else if (/Mac/i.test(ua)) os = 'macOS';
            else if (/Android/i.test(ua)) os = 'Android';
            else if (/Linux/i.test(ua)) os = 'Linux';
        }
        if (!browser) {
            if (/Edg\//i.test(ua)) browser = 'Edge';
            else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome';
            else if (/Firefox\//i.test(ua)) browser = 'Firefox';
            else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';
        }

        let transports = [];
        try {
            const fromGetter = attestation && attestation.response && attestation.response.getTransports
                ? attestation.response.getTransports()
                : null;
            transports = Array.isArray(fromGetter)
                ? fromGetter
                : attestation && attestation.response && Array.isArray(attestation.response.transports)
                    ? attestation.response.transports
                    : [];
        } catch (_e) {
            transports = [];
        }
        let method = '';
        // Append a method only when it adds distinguishing info. Platform
        // (internal) credentials are left unsuffixed — "<Browser> on <OS>"
        // already identifies them, and the nickname is stored statically so a
        // device-relative label would be wrong when viewed from elsewhere.
        if (transports.includes('hybrid')) method = 'Phone';
        else if (transports.some((t) => ['usb', 'nfc', 'ble'].includes(t))) method = 'Security key';

        const where = [browser, os].filter(Boolean).join(' on ');
        return [where || 'Passkey', method].filter(Boolean).join(' · ');
    }

    // Format a stored timestamp for the passkey list ("Added <date>").
    function formatPasskeyDate(value) {
        if (!value) return 'just now';
        const ts = new Date(value.includes('Z') || value.includes('T') ? value : value.replace(' ', 'T') + 'Z');
        if (Number.isNaN(ts.getTime())) return 'recently';
        return ts.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    }

    window.PasskeyHelpers = {
        withTimeout,
        describePasskeyError,
        describePasskeyDevice,
        formatPasskeyDate
    };
})();
