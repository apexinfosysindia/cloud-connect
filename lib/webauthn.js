const crypto = require('crypto');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const { providerNameForAaguid } = require('./passkey-aaguids');

/**
 * WebAuthn / FIDO2 passkey helper.
 *
 * Wraps @simplewebauthn/server@9 (the last release that supports Node 18) and
 * owns all credential + challenge persistence for both portals. A "principal"
 * object identifies who the ceremony is for:
 *
 *   customer: { kind: 'customer', subject: <email>, userId: <users.id> }
 *   admin:    { kind: 'admin',    subject: <ADMIN_EMAIL>, adminEmail: <ADMIN_EMAIL> }
 *
 * `subject` is the challenge key + WebAuthn userName. Credentials are scoped by
 * users.id (customer) or admin_email (admin) so the two namespaces never mix.
 *
 * Challenges are single-use and persisted in webauthn_challenges (DB-backed,
 * mirroring email_verification_tokens) so a ceremony survives a restart and
 * works across workers — no in-memory Map.
 */
module.exports = function ({ dbGet, dbRun, dbAll, config, utils }) {
    const CHALLENGE_TTL_MINUTES = 5;
    const CEREMONY_TIMEOUT_MS = 60000;

    function envValue(name) {
        return utils.sanitizeString(process.env[name] || '', 512);
    }

    // Resolve the Relying-Party config for a portal. Defaults derive from the
    // existing host config; env overrides exist so localhost dev (where the
    // origin is http://localhost:3000 and the RP ID is "localhost") works.
    function getRpConfig(kind) {
        const isAdmin = kind === 'admin';
        const host = isAdmin
            ? envValue('WEBAUTHN_RP_ID_ADMIN') || config.ADMIN_PORTAL_HOST
            : envValue('WEBAUTHN_RP_ID_CUSTOMER') || config.CUSTOMER_PORTAL_HOST;
        const explicitOrigin = isAdmin ? envValue('WEBAUTHN_ORIGIN_ADMIN') : envValue('WEBAUTHN_ORIGIN_CUSTOMER');
        const origin = explicitOrigin || `https://${host}`;

        return {
            rpID: host,
            origin,
            rpName: isAdmin ? 'ApexOS Cloud Connect Admin' : 'ApexOS Cloud Connect'
        };
    }

    function isAdminPasskeyBreakGlass() {
        return process.env.ADMIN_PASSKEY_BREAK_GLASS === '1';
    }

    // The WebAuthn user handle (user.id) must be 1–64 BYTES, transported as a
    // base64url string. @simplewebauthn/browser@9 decodes options.user.id via
    // base64URLStringToBuffer before calling navigator.credentials.create, so a
    // raw value like "1" decodes to 0 bytes — Apple tolerates that, but Dashlane
    // and Microsoft Authenticator reject the empty handle and refuse to enrol.
    // We hash a stable, namespaced identifier to a fixed 32 bytes and base64url-
    // encode it: always within the 1–64 byte limit, deterministic per principal
    // (same user → same handle across logins), and valid for every authenticator.
    function deriveUserHandle(principal) {
        const stable =
            principal.kind === 'customer' ? `customer:${principal.userId}` : `admin:${principal.subject || ''}`;
        const digest = crypto.createHash('sha256').update(stable).digest(); // 32 bytes
        return isoBase64URL.fromBuffer(new Uint8Array(digest));
    }

    function decodeTransports(value) {
        const parsed = utils.parseJsonSafe(value, null);
        return Array.isArray(parsed) && parsed.length ? parsed : undefined;
    }

    // ── Credential persistence ─────────────────────────────────────────────
    function listCredentials(principal) {
        if (principal.kind === 'customer') {
            return dbAll(
                `SELECT * FROM webauthn_credentials WHERE account_kind = 'customer' AND user_id = ? ORDER BY created_at ASC`,
                [principal.userId]
            );
        }
        return dbAll(
            `SELECT * FROM webauthn_credentials WHERE account_kind = 'admin' AND admin_email = ? ORDER BY created_at ASC`,
            [principal.adminEmail]
        );
    }

    async function countCredentials(principal) {
        const row =
            principal.kind === 'customer'
                ? await dbGet(
                      `SELECT COUNT(*) AS c FROM webauthn_credentials WHERE account_kind = 'customer' AND user_id = ?`,
                      [principal.userId]
                  )
                : await dbGet(
                      `SELECT COUNT(*) AS c FROM webauthn_credentials WHERE account_kind = 'admin' AND admin_email = ?`,
                      [principal.adminEmail]
                  );
        return Number(row?.c || 0);
    }

    function getCredentialByCredentialId(principal, credentialId) {
        if (principal.kind === 'customer') {
            return dbGet(
                `SELECT * FROM webauthn_credentials WHERE credential_id = ? AND account_kind = 'customer' AND user_id = ?`,
                [credentialId, principal.userId]
            );
        }
        return dbGet(
            `SELECT * FROM webauthn_credentials WHERE credential_id = ? AND account_kind = 'admin' AND admin_email = ?`,
            [credentialId, principal.adminEmail]
        );
    }

    async function insertCredential(principal, cred, nickname) {
        const result = await dbRun(
            `INSERT INTO webauthn_credentials
                (user_id, account_kind, admin_email, credential_id, public_key, sign_count, transports, aaguid, nickname)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                principal.kind === 'customer' ? principal.userId : null,
                principal.kind,
                principal.kind === 'admin' ? principal.adminEmail : null,
                cred.credentialId,
                cred.publicKey,
                Number(cred.counter) || 0,
                cred.transports ? JSON.stringify(cred.transports) : null,
                cred.aaguid || null,
                utils.sanitizeString(nickname, 80)
            ]
        );
        return result.lastID;
    }

    async function deleteCredential(principal, credentialRowId) {
        const result =
            principal.kind === 'customer'
                ? await dbRun(
                      `DELETE FROM webauthn_credentials WHERE id = ? AND account_kind = 'customer' AND user_id = ?`,
                      [credentialRowId, principal.userId]
                  )
                : await dbRun(
                      `DELETE FROM webauthn_credentials WHERE id = ? AND account_kind = 'admin' AND admin_email = ?`,
                      [credentialRowId, principal.adminEmail]
                  );
        return Number(result?.changes || 0);
    }

    // Toggle the users.passkey_2fa_enabled enforcement flag (customer only;
    // admin enforcement is derived from credential count, not a flag).
    function setCustomerPasskeyEnabled(userId, enabled) {
        return dbRun(`UPDATE users SET passkey_2fa_enabled = ? WHERE id = ?`, [enabled ? 1 : 0, userId]);
    }

    // ── Challenge persistence (single-use) ─────────────────────────────────
    async function storeChallenge(principal, ceremony, challenge) {
        // Only one in-flight challenge per (subject, kind, ceremony); also prune
        // anything expired so the table can't grow unbounded.
        await dbRun(
            `DELETE FROM webauthn_challenges WHERE (subject = ? AND account_kind = ? AND ceremony = ?) OR expires_at <= datetime('now')`,
            [principal.subject, principal.kind, ceremony]
        );
        await dbRun(
            `INSERT INTO webauthn_challenges (subject, account_kind, ceremony, challenge, expires_at)
             VALUES (?, ?, ?, ?, datetime('now', ?))`,
            [principal.subject, principal.kind, ceremony, challenge, `+${CHALLENGE_TTL_MINUTES} minutes`]
        );
    }

    async function consumeChallenge(principal, ceremony) {
        const row = await dbGet(
            `SELECT id, challenge FROM webauthn_challenges
             WHERE subject = ? AND account_kind = ? AND ceremony = ? AND expires_at > datetime('now')
             ORDER BY id DESC LIMIT 1`,
            [principal.subject, principal.kind, ceremony]
        );
        // Single-use: remove every challenge for this tuple regardless of match.
        await dbRun(`DELETE FROM webauthn_challenges WHERE subject = ? AND account_kind = ? AND ceremony = ?`, [
            principal.subject,
            principal.kind,
            ceremony
        ]);
        return row?.challenge || null;
    }

    // ── Registration ceremony ──────────────────────────────────────────────
    async function beginRegistration(principal) {
        const { rpID, rpName } = getRpConfig(principal.kind);
        const existing = await listCredentials(principal);
        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userID: deriveUserHandle(principal),
            userName: principal.subject,
            userDisplayName: principal.displayName || principal.subject,
            timeout: CEREMONY_TIMEOUT_MS,
            attestationType: 'none',
            // Pin the credential algorithms to ES256 (-7) and RS256 (-257). The
            // library default also offers Ed25519 (-8), which several third-party
            // password managers (notably Dashlane desktop on Chrome) choke on —
            // their popup dies with "An error occurred during the security
            // verification" while Apple/iCloud Keychain tolerate it. Major sites
            // send exactly these two; dropping -8 unblocks Dashlane and is inert
            // for every authenticator that already worked. (Lost in an earlier
            // branch revert; restored here.)
            supportedAlgorithmIDs: [-7, -257],
            excludeCredentials: existing.map((c) => ({
                // Dedup is by credential id; transports is only an optional
                // routing hint, so we omit it and keep the entry minimal.
                id: isoBase64URL.toBuffer(c.credential_id),
                type: 'public-key'
            })),
            authenticatorSelection: {
                // Discoverable credentials (resident key) so the passkey is
                // usable without typing a username. userVerification is
                // 'preferred' (the verifier uses requireUserVerification:false),
                // which is broadly compatible and lets biometrics be used when
                // available.
                residentKey: 'required',
                userVerification: 'preferred'
            }
        });
        await storeChallenge(principal, 'registration', options.challenge);
        return options;
    }

    async function finishRegistration(principal, response) {
        const { rpID, origin } = getRpConfig(principal.kind);
        const expectedChallenge = await consumeChallenge(principal, 'registration');
        if (!expectedChallenge) {
            return { verified: false, error: 'challenge_expired' };
        }

        let verification;
        try {
            verification = await verifyRegistrationResponse({
                response,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: false
            });
        } catch (error) {
            return { verified: false, error: error.message || 'verification_failed' };
        }

        if (!verification.verified || !verification.registrationInfo) {
            return { verified: false, error: 'not_verified' };
        }

        const info = verification.registrationInfo;
        return {
            verified: true,
            credential: {
                credentialId: isoBase64URL.fromBuffer(info.credentialID),
                publicKey: isoBase64URL.fromBuffer(info.credentialPublicKey),
                counter: info.counter,
                aaguid: info.aaguid || null,
                transports: Array.isArray(response?.response?.transports) ? response.response.transports : null
            }
        };
    }

    // ── Authentication ceremony ────────────────────────────────────────────
    async function beginAuthentication(principal) {
        const { rpID } = getRpConfig(principal.kind);
        const creds = await listCredentials(principal);
        if (!creds.length) {
            return null;
        }
        const options = await generateAuthenticationOptions({
            rpID,
            timeout: CEREMONY_TIMEOUT_MS,
            userVerification: 'preferred',
            allowCredentials: creds.map((c) => ({
                id: isoBase64URL.toBuffer(c.credential_id),
                type: 'public-key',
                transports: decodeTransports(c.transports)
            }))
        });
        await storeChallenge(principal, 'authentication', options.challenge);
        return options;
    }

    async function finishAuthentication(principal, response) {
        const { rpID, origin } = getRpConfig(principal.kind);
        const expectedChallenge = await consumeChallenge(principal, 'authentication');
        if (!expectedChallenge) {
            return { verified: false, error: 'challenge_expired' };
        }

        const credentialId = utils.sanitizeString(response?.id, 1023);
        if (!credentialId) {
            return { verified: false, error: 'missing_credential_id' };
        }

        const cred = await getCredentialByCredentialId(principal, credentialId);
        if (!cred) {
            return { verified: false, error: 'unknown_credential' };
        }

        let verification;
        try {
            verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: false,
                authenticator: {
                    credentialID: isoBase64URL.toBuffer(cred.credential_id),
                    credentialPublicKey: isoBase64URL.toBuffer(cred.public_key),
                    counter: Number(cred.sign_count) || 0,
                    transports: decodeTransports(cred.transports)
                }
            });
        } catch (error) {
            return { verified: false, error: error.message || 'verification_failed' };
        }

        if (!verification.verified) {
            return { verified: false, error: 'not_verified' };
        }

        await dbRun(`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?`, [
            Number(verification.authenticationInfo.newCounter) || 0,
            cred.id
        ]);

        return { verified: true, credentialRowId: cred.id };
    }

    // ── Usernameless / discoverable authentication ─────────────────────────
    // A passkey button with no email typed: the browser shows ALL discoverable
    // credentials for this RP and the user picks one. allowCredentials is empty;
    // the user is resolved AFTER the assertion, from the returned credential id.
    // The challenge is keyed by its own value (subject = 'discoverable:<chal>')
    // since there's no email to key on; the client echoes the challenge back on
    // verify so we can reconstruct that single-use key.
    async function beginDiscoverableAuthentication(kind = 'customer') {
        const { rpID } = getRpConfig(kind);
        const options = await generateAuthenticationOptions({
            rpID,
            timeout: CEREMONY_TIMEOUT_MS,
            userVerification: 'preferred',
            allowCredentials: []
        });
        await storeChallenge(
            { subject: `discoverable:${options.challenge}`, kind },
            'authentication',
            options.challenge
        );
        return options;
    }

    // Customer-only credential lookup by id ALONE (no user_id), so a discoverable
    // assertion can be traced back to its owner.
    function getCustomerCredentialByCredentialId(credentialId) {
        return dbGet(`SELECT * FROM webauthn_credentials WHERE credential_id = ? AND account_kind = 'customer'`, [
            credentialId
        ]);
    }

    async function finishDiscoverableAuthentication(kind, challenge, response) {
        const { rpID, origin } = getRpConfig(kind);
        const expectedChallenge = await consumeChallenge(
            { subject: `discoverable:${challenge}`, kind },
            'authentication'
        );
        if (!expectedChallenge) {
            return { verified: false, error: 'challenge_expired' };
        }

        const credentialId = utils.sanitizeString(response?.id, 1023);
        if (!credentialId) {
            return { verified: false, error: 'missing_credential_id' };
        }

        const cred = await getCustomerCredentialByCredentialId(credentialId);
        if (!cred) {
            return { verified: false, error: 'unknown_credential' };
        }

        let verification;
        try {
            verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                requireUserVerification: false,
                authenticator: {
                    credentialID: isoBase64URL.toBuffer(cred.credential_id),
                    credentialPublicKey: isoBase64URL.toBuffer(cred.public_key),
                    counter: Number(cred.sign_count) || 0,
                    transports: decodeTransports(cred.transports)
                }
            });
        } catch (error) {
            return { verified: false, error: error.message || 'verification_failed' };
        }

        if (!verification.verified) {
            return { verified: false, error: 'not_verified' };
        }

        await dbRun(`UPDATE webauthn_credentials SET sign_count = ?, last_used_at = datetime('now') WHERE id = ?`, [
            Number(verification.authenticationInfo.newCounter) || 0,
            cred.id
        ]);

        return { verified: true, userId: cred.user_id };
    }

    function serializeCredential(row) {
        // Resolve a friendly provider name from the AAGUID (e.g. "1Password").
        // This is the most useful label for telling passkeys apart — especially
        // duplicates enrolled across different managers, which the browser-
        // derived nickname ("Chrome on macOS") cannot distinguish. Falls back to
        // the stored UA nickname when the AAGUID is zero/unknown (notably
        // hybrid/cross-device credentials, which carry an all-zero AAGUID for
        // privacy). The raw nickname is still returned for secondary context.
        const provider = providerNameForAaguid(row.aaguid);
        const nickname = row.nickname || null;
        return {
            id: row.id,
            nickname,
            display_name: provider || nickname || 'Passkey',
            created_at: row.created_at,
            last_used_at: row.last_used_at || null
        };
    }

    return {
        isAdminPasskeyBreakGlass,
        listCredentials,
        countCredentials,
        insertCredential,
        deleteCredential,
        setCustomerPasskeyEnabled,
        beginRegistration,
        finishRegistration,
        beginAuthentication,
        finishAuthentication,
        beginDiscoverableAuthentication,
        finishDiscoverableAuthentication,
        serializeCredential
    };
};
