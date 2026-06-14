/**
 * AAGUID → human provider name map for passkey labelling.
 *
 * The AAGUID identifies the authenticator/credential-provider MODEL (e.g.
 * "1Password", "Apple Passwords"), which is far more useful as a default
 * passkey name than the browser-derived "Chrome on macOS" string — especially
 * for telling duplicate passkeys apart when the same account enrols one in each
 * of several password managers.
 *
 * Values are pinned from the community-maintained registry
 * (github.com/passkeydeveloper/passkey-authenticator-aaguids), verified at
 * authoring time. We bundle a curated subset (the consumer providers our users
 * actually use) rather than fetch at runtime — no network dependency on a
 * latency-sensitive enrolment path, and the list changes rarely.
 *
 * IMPORTANT — known blind spot: credentials created over the cross-device
 * "hybrid" (QR / phone-as-authenticator) flow arrive with an ALL-ZERO AAGUID
 * (00000000-0000-0000-0000-000000000000) for privacy. Roaming security keys
 * may also report zero. So this map resolves "this device" software providers
 * well, but CANNOT attribute a hybrid passkey to its real manager — those fall
 * back to the browser/UA-derived name. Apple additionally uses two values:
 * "Apple Passwords" (fbfc3007…) for platform and "iCloud Keychain (Managed)"
 * for MDM-managed devices.
 */

// Dashed lowercase UUID → display name. SimpleWebAuthn returns the AAGUID in
// exactly this format, and our DB stores it verbatim, so keys match directly.
const AAGUID_NAMES = {
    // ── Apple ──
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
    // ── Google ──
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    // ── Microsoft ──
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    // ── Password managers ──
    'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
    '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
    'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
    'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass',
    'f3809540-7f14-49c1-a8b3-8f813b225541': 'Enpass',
    '50726f74-6f6e-5061-7373-50726f746f6e': 'Proton Pass',
    'fdb141b2-5d84-443e-8a35-4698c205a502': 'KeePassXC',
    'eaecdef2-1c31-5634-8639-f1cbd9c00a08': 'KeePassDX',
    '9addb28c-b46f-4402-808f-019651441ff3': 'KeePassPasskey',
    '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
    // ── Browser-family software authenticators ──
    'b5397666-4885-aa6b-cebf-e52262a439a2': 'Chromium',
    'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome',
    '771b48fd-d3d4-4f74-9232-fc157ab0507a': 'Edge',
    // ── Roaming security keys (common) ──
    '39a5647e-1853-446c-a1f6-a79bae9f5bc7': 'IDmelon'
};

// The all-zero AAGUID is the spec's "no attestation / privacy" value, returned
// for hybrid (cross-device) credentials and many roaming keys. It carries no
// provider information, so it must NOT resolve to a name.
const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

/**
 * Resolve an AAGUID to a provider display name.
 * @param {string|null|undefined} aaguid dashed-lowercase UUID as stored
 * @returns {string|null} the provider name, or null when unknown/zero/absent
 *   (caller should fall back to its own browser/UA-derived label).
 */
function providerNameForAaguid(aaguid) {
    if (!aaguid || typeof aaguid !== 'string') {
        return null;
    }
    const key = aaguid.trim().toLowerCase();
    if (!key || key === ZERO_AAGUID) {
        return null;
    }
    return AAGUID_NAMES[key] || null;
}

module.exports = { AAGUID_NAMES, ZERO_AAGUID, providerNameForAaguid };
