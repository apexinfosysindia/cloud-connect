require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const CUSTOMER_PORTAL_HOST = process.env.CUSTOMER_PORTAL_HOST || 'oasis.apexinfosys.in';
const ADMIN_PORTAL_HOST = process.env.ADMIN_PORTAL_HOST || 'vista.apexinfosys.in';
const CLOUD_BASE_DOMAIN = process.env.CLOUD_BASE_DOMAIN || 'cloud.apexinfosys.in';
const DEVICE_TUNNEL_HOST = process.env.DEVICE_TUNNEL_HOST || CLOUD_BASE_DOMAIN;
const ADMIN_SSH_JUMP_HOST = 'cloud.apexinfosys.in';
const ADMIN_SSH_JUMP_USER = 'fleetadmin';
const ADMIN_SSH_JUMP_PORT = 22;
const ADMIN_SSH_TARGET_HOST = '127.0.0.1';
const GOOGLE_HOME_CLIENT_ID = process.env.GOOGLE_HOME_CLIENT_ID || '';
const GOOGLE_HOME_CLIENT_SECRET = process.env.GOOGLE_HOME_CLIENT_SECRET || '';
const GOOGLE_HOME_REDIRECT_URI_HOSTS = (
    process.env.GOOGLE_HOME_REDIRECT_URI_HOSTS || 'oauth-redirect.googleusercontent.com'
)
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
const GOOGLE_HOME_AUTH_CODE_TTL_SECONDS = Number(process.env.GOOGLE_HOME_AUTH_CODE_TTL_SECONDS || 600);
const GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS || 3600);
const GOOGLE_HOME_COMMAND_TTL_SECONDS = Number(process.env.GOOGLE_HOME_COMMAND_TTL_SECONDS || 45);
const GOOGLE_HOMEGRAPH_SCOPE = 'https://www.googleapis.com/auth/homegraph';
const GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const GOOGLE_HOMEGRAPH_API_BASE_URL = 'https://homegraph.googleapis.com/v1';
const GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS = Number(process.env.GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS || 2500);
const GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS = Number(process.env.GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS || 1200);
const GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED = process.env.GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED === '0' ? false : true;
const GOOGLE_DEBUG_ENDPOINTS_ENABLED = process.env.GOOGLE_DEBUG_ENDPOINTS_ENABLED === '1';
// --- Amazon Alexa Smart Home (mirrors the Google Home block above) ---
// Portal-issued OAuth credentials the Alexa skill presents to us for account
// linking + the token endpoint.
const ALEXA_CLIENT_ID = process.env.ALEXA_CLIENT_ID || '';
const ALEXA_CLIENT_SECRET = process.env.ALEXA_CLIENT_SECRET || '';
// Our Login with Amazon security-profile credentials, used to refresh the LWA
// tokens Amazon grants us at AcceptGrant so we can call the Event Gateway.
const ALEXA_LWA_CLIENT_ID = process.env.ALEXA_LWA_CLIENT_ID || '';
const ALEXA_LWA_CLIENT_SECRET = process.env.ALEXA_LWA_CLIENT_SECRET || '';
// 32-byte key (hex or base64) for AES-256-GCM encryption of LWA tokens at rest.
const ALEXA_LWA_TOKEN_ENC_KEY = process.env.ALEXA_LWA_TOKEN_ENC_KEY || '';
const ALEXA_LWA_TOKEN_URI = process.env.ALEXA_LWA_TOKEN_URI || 'https://api.amazon.com/auth/o2/token';
const ALEXA_EVENT_GATEWAY_URL = process.env.ALEXA_EVENT_GATEWAY_URL || 'https://api.amazonalexa.com/v3/events';
// Alexa skill id (amzn1.ask.skill.…). Required to call Amazon's customer-facing
// "disable skill + unlink" API on portal unlink (DELETE /v1/users/~current/skills/
// {id}/enablement), which is what actually stops Amazon's relink nag. When unset,
// the unlink still drops devices + revokes our tokens, but cannot disable the skill
// at Amazon (falls back to asking the user to disable it in the Alexa app).
const ALEXA_SKILL_ID = process.env.ALEXA_SKILL_ID || '';
const ALEXA_REDIRECT_URI_HOSTS = (
    process.env.ALEXA_REDIRECT_URI_HOSTS || 'pitangui.amazon.com,layla.amazon.com,alexa.amazon.co.jp'
)
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
const ALEXA_AUTH_CODE_TTL_SECONDS = Number(process.env.ALEXA_AUTH_CODE_TTL_SECONDS || 600);
const ALEXA_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ALEXA_ACCESS_TOKEN_TTL_SECONDS || 3600);
const ALEXA_COMMAND_TTL_SECONDS = Number(process.env.ALEXA_COMMAND_TTL_SECONDS || 45);
const ALEXA_ADD_OR_UPDATE_DEBOUNCE_MS = Number(process.env.ALEXA_ADD_OR_UPDATE_DEBOUNCE_MS || 2500);
const ALEXA_CHANGE_REPORT_DEBOUNCE_MS = Number(process.env.ALEXA_CHANGE_REPORT_DEBOUNCE_MS || 1200);
const ALEXA_REPORT_STATE_ENABLED = process.env.ALEXA_REPORT_STATE_ENABLED === '0' ? false : true;
const ALEXA_DEBUG_ENDPOINTS_ENABLED = process.env.ALEXA_DEBUG_ENDPOINTS_ENABLED === '1';
// Shared secret the AWS Lambda forwarder echoes in X-Alexa-Forwarder-Secret.
// When set, /api/alexa/fulfillment rejects any request whose header does not
// match — defense in depth so directives can't be POSTed to the portal
// directly, bypassing the Lambda. When empty (default), the check is skipped
// so an un-provisioned deployment keeps working (the bearer token in each
// directive remains the primary auth either way).
const ALEXA_FORWARDER_SECRET = process.env.ALEXA_FORWARDER_SECRET || '';
const ALLOWED_CORS_ORIGINS = (process.env.ALLOWED_CORS_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
const PORTAL_SESSION_COOKIE_NAME = 'apx_portal_session';
const PORTAL_SESSION_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const PORTAL_SESSION_COOKIE_SECURE = process.env.PORTAL_COOKIE_SECURE === '0' ? false : true;
const PORTAL_SESSION_COOKIE_DOMAIN = process.env.PORTAL_COOKIE_DOMAIN || '.apexinfosys.in';
const DEVICE_HEARTBEAT_TIMEOUT_SECONDS = Number(process.env.DEVICE_HEARTBEAT_TIMEOUT_SECONDS || 45);
const DEVICE_HEARTBEAT_INTERVAL_SECONDS = Number(process.env.DEVICE_HEARTBEAT_INTERVAL_SECONDS || 20);
const DEVICE_TUNNEL_PORT_MIN = Number(process.env.DEVICE_TUNNEL_PORT_MIN || 22000);
const DEVICE_TUNNEL_PORT_MAX = Number(process.env.DEVICE_TUNNEL_PORT_MAX || 22999);
const DEVICE_TOKEN_PREFIX = 'dvc_';
const RAZORPAY_PLAN_ID_MONTHLY = process.env.RAZORPAY_PLAN_ID_MONTHLY || '';
const RAZORPAY_PLAN_ID_ANNUAL = process.env.RAZORPAY_PLAN_ID_ANNUAL || process.env.RAZORPAY_PLAN_ID || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM_NAME = process.env.RESEND_FROM_NAME || 'ApexOS Cloud Connect';
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || 'noreply@apexinfosys.in';
const EMAIL_VERIFICATION_TOKEN_TTL_MS = Number(process.env.EMAIL_VERIFICATION_TOKEN_TTL_HOURS || 24) * 60 * 60 * 1000;
const PASSWORD_RESET_TOKEN_TTL_MS = Number(process.env.PASSWORD_RESET_TOKEN_TTL_HOURS || 1) * 60 * 60 * 1000;
// Email sign-in code (passwordless-login emergency fallback): short-lived by
// design — long enough to switch to the inbox and copy it, short enough that a
// leaked code is useless minutes later.
const LOGIN_OTP_TTL_MS = Number(process.env.LOGIN_OTP_TTL_MINUTES || 10) * 60 * 1000;
const LOGIN_OTP_MAX_ATTEMPTS = Number(process.env.LOGIN_OTP_MAX_ATTEMPTS || 5);

// --- Customer SSO / social sign-in (Google, Microsoft, Apple) ---
// We act as the OIDC *client* here (the opposite direction from the Google Home
// / Alexa OAuth, where the portal is the provider). Each provider self-enables
// ONLY when its credentials are present — mirroring the GOOGLE_HOME_CLIENT_ID
// presence-flag pattern above — so an un-provisioned deployment renders no SSO
// buttons and every /api/auth/sso/* route 404s. No third-party broker: we talk
// to each provider's own OIDC discovery + token endpoints directly.
//
// SSO_BASE_URL is the public https origin the providers redirect back to; the
// redirect_uri registered in each provider console must be
// `${SSO_BASE_URL}/api/auth/sso/<provider>/callback`. It defaults to the
// customer portal host. The Apple block is a Services ID + a developer key
// (Team ID + Key ID + PKCS8 private key) from which we mint a short-lived
// ES256 client_secret JWT per request (Apple does not issue a static secret).
const SSO_BASE_URL = (process.env.SSO_BASE_URL || `https://${CUSTOMER_PORTAL_HOST}`).replace(/\/+$/, '');
const SSO_GOOGLE_CLIENT_ID = process.env.SSO_GOOGLE_CLIENT_ID || '';
const SSO_GOOGLE_CLIENT_SECRET = process.env.SSO_GOOGLE_CLIENT_SECRET || '';
const SSO_MICROSOFT_CLIENT_ID = process.env.SSO_MICROSOFT_CLIENT_ID || '';
const SSO_MICROSOFT_CLIENT_SECRET = process.env.SSO_MICROSOFT_CLIENT_SECRET || '';
const SSO_MICROSOFT_TENANT = process.env.SSO_MICROSOFT_TENANT || 'common';
const SSO_APPLE_CLIENT_ID = process.env.SSO_APPLE_CLIENT_ID || ''; // Apple "Services ID"
const SSO_APPLE_TEAM_ID = process.env.SSO_APPLE_TEAM_ID || '';
const SSO_APPLE_KEY_ID = process.env.SSO_APPLE_KEY_ID || '';
// Normalize the Apple .p8 (PKCS8 PEM) into a key that node:crypto can parse,
// however it survived the journey into .env. People paste it three ways:
//   1) one line with literal "\n" escapes, 2) genuine multi-line, or 3) mangled
//   to a single line with spaces where the newlines were (the common, silent
//   breakage). All three normalize to the same valid PEM: restore "\n", then if
//   no real newlines remain, rebuild by re-chunking the base64 body to 64 cols.
function normalizeApplePrivateKey(raw) {
    const s = String(raw || '')
        .replace(/\\n/g, '\n')
        .trim();
    if (!s) return '';
    if (s.includes('\n')) return s; // already multi-line — good as-is
    const m = s.match(/-----BEGIN [A-Z ]+-----(.*)-----END [A-Z ]+-----/s);
    if (!m) return s; // not a recognizable PEM; leave it (sign will fail loudly)
    const body = m[1].replace(/\s+/g, '');
    const lines = body.match(/.{1,64}/g) || [];
    return ['-----BEGIN PRIVATE KEY-----', ...lines, '-----END PRIVATE KEY-----'].join('\n');
}
const SSO_APPLE_PRIVATE_KEY = normalizeApplePrivateKey(process.env.SSO_APPLE_PRIVATE_KEY);

const SSO = {
    baseUrl: SSO_BASE_URL,
    // Each provider: enabled flag (creds present) + the metadata lib/sso.js needs.
    // `issuer` is the OIDC discovery origin; `scope` is the minimal claim set.
    providers: {
        google: {
            id: 'google',
            label: 'Google',
            enabled: Boolean(SSO_GOOGLE_CLIENT_ID && SSO_GOOGLE_CLIENT_SECRET),
            issuer: 'https://accounts.google.com',
            clientId: SSO_GOOGLE_CLIENT_ID,
            clientSecret: SSO_GOOGLE_CLIENT_SECRET,
            scope: 'openid email profile'
        },
        microsoft: {
            id: 'microsoft',
            label: 'Microsoft',
            enabled: Boolean(SSO_MICROSOFT_CLIENT_ID && SSO_MICROSOFT_CLIENT_SECRET),
            issuer: `https://login.microsoftonline.com/${SSO_MICROSOFT_TENANT}/v2.0`,
            clientId: SSO_MICROSOFT_CLIENT_ID,
            clientSecret: SSO_MICROSOFT_CLIENT_SECRET,
            scope: 'openid email profile'
        },
        apple: {
            id: 'apple',
            label: 'Apple',
            // Apple needs the Services ID plus a full signing key to mint the
            // client_secret JWT, so all four must be present to enable it.
            enabled: Boolean(SSO_APPLE_CLIENT_ID && SSO_APPLE_TEAM_ID && SSO_APPLE_KEY_ID && SSO_APPLE_PRIVATE_KEY),
            issuer: 'https://appleid.apple.com',
            clientId: SSO_APPLE_CLIENT_ID,
            teamId: SSO_APPLE_TEAM_ID,
            keyId: SSO_APPLE_KEY_ID,
            privateKey: SSO_APPLE_PRIVATE_KEY,
            // Apple returns name/email only on first consent; request them then.
            // response_mode=form_post is required for the 'email' scope.
            scope: 'openid email name'
        }
    }
};

module.exports = {
    CUSTOMER_PORTAL_HOST,
    ADMIN_PORTAL_HOST,
    CLOUD_BASE_DOMAIN,
    DEVICE_TUNNEL_HOST,
    ADMIN_SSH_JUMP_HOST,
    ADMIN_SSH_JUMP_USER,
    ADMIN_SSH_JUMP_PORT,
    ADMIN_SSH_TARGET_HOST,
    GOOGLE_HOME_CLIENT_ID,
    GOOGLE_HOME_CLIENT_SECRET,
    GOOGLE_HOME_REDIRECT_URI_HOSTS,
    GOOGLE_HOME_AUTH_CODE_TTL_SECONDS,
    GOOGLE_HOME_ACCESS_TOKEN_TTL_SECONDS,
    GOOGLE_HOME_COMMAND_TTL_SECONDS,
    GOOGLE_HOMEGRAPH_SCOPE,
    GOOGLE_HOMEGRAPH_DEFAULT_TOKEN_URI,
    GOOGLE_HOMEGRAPH_API_BASE_URL,
    GOOGLE_HOMEGRAPH_REQUEST_SYNC_DEBOUNCE_MS,
    GOOGLE_HOMEGRAPH_REPORT_STATE_DEBOUNCE_MS,
    GOOGLE_HOMEGRAPH_REPORT_STATE_ENABLED,
    GOOGLE_DEBUG_ENDPOINTS_ENABLED,
    ALEXA_CLIENT_ID,
    ALEXA_CLIENT_SECRET,
    ALEXA_LWA_CLIENT_ID,
    ALEXA_LWA_CLIENT_SECRET,
    ALEXA_LWA_TOKEN_ENC_KEY,
    ALEXA_LWA_TOKEN_URI,
    ALEXA_EVENT_GATEWAY_URL,
    ALEXA_SKILL_ID,
    ALEXA_REDIRECT_URI_HOSTS,
    ALEXA_AUTH_CODE_TTL_SECONDS,
    ALEXA_ACCESS_TOKEN_TTL_SECONDS,
    ALEXA_COMMAND_TTL_SECONDS,
    ALEXA_ADD_OR_UPDATE_DEBOUNCE_MS,
    ALEXA_CHANGE_REPORT_DEBOUNCE_MS,
    ALEXA_REPORT_STATE_ENABLED,
    ALEXA_DEBUG_ENDPOINTS_ENABLED,
    ALEXA_FORWARDER_SECRET,
    ALLOWED_CORS_ORIGINS,
    PORTAL_SESSION_COOKIE_NAME,
    PORTAL_SESSION_COOKIE_MAX_AGE_MS,
    PORTAL_SESSION_COOKIE_SECURE,
    PORTAL_SESSION_COOKIE_DOMAIN,
    DEVICE_HEARTBEAT_TIMEOUT_SECONDS,
    DEVICE_HEARTBEAT_INTERVAL_SECONDS,
    DEVICE_TUNNEL_PORT_MIN,
    DEVICE_TUNNEL_PORT_MAX,
    DEVICE_TOKEN_PREFIX,
    RAZORPAY_PLAN_ID_MONTHLY,
    RAZORPAY_PLAN_ID_ANNUAL,
    RESEND_API_KEY,
    RESEND_FROM_NAME,
    RESEND_FROM_EMAIL,
    EMAIL_VERIFICATION_TOKEN_TTL_MS,
    PASSWORD_RESET_TOKEN_TTL_MS,
    LOGIN_OTP_TTL_MS,
    LOGIN_OTP_MAX_ATTEMPTS,
    SSO
};
