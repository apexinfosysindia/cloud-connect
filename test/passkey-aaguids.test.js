const { test } = require('node:test');
const assert = require('node:assert');
const { providerNameForAaguid, AAGUID_NAMES, ZERO_AAGUID } = require('../lib/passkey-aaguids');

// These mappings are security-relevant labels shown to users to tell their
// passkeys apart. Pin the verified values so an accidental edit can't silently
// mislabel a credential (e.g. show "1Password" for a Dashlane key).
test('resolves known consumer providers to their exact names', () => {
    const cases = {
        'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'Apple Passwords',
        'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (Managed)',
        'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
        'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
        '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
        'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
        '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
        'b5397666-4885-aa6b-cebf-e52262a439a2': 'Chromium'
    };
    for (const [aaguid, name] of Object.entries(cases)) {
        assert.equal(providerNameForAaguid(aaguid), name, `${aaguid} should resolve to ${name}`);
    }
});

test('the all-zero AAGUID never resolves to a provider (hybrid/roaming privacy value)', () => {
    assert.equal(providerNameForAaguid(ZERO_AAGUID), null);
    assert.equal(providerNameForAaguid('00000000-0000-0000-0000-000000000000'), null);
});

test('absent / malformed / unknown AAGUIDs return null so the caller can fall back', () => {
    assert.equal(providerNameForAaguid(null), null);
    assert.equal(providerNameForAaguid(undefined), null);
    assert.equal(providerNameForAaguid(''), null);
    assert.equal(providerNameForAaguid('   '), null);
    assert.equal(providerNameForAaguid(12345), null);
    assert.equal(providerNameForAaguid('not-a-real-aaguid'), null);
    assert.equal(providerNameForAaguid('ffffffff-ffff-ffff-ffff-ffffffffffff'), null);
});

test('lookup is case-insensitive and tolerates surrounding whitespace', () => {
    assert.equal(providerNameForAaguid('BADA5566-A7AA-401F-BD96-45619A55120D'), '1Password');
    assert.equal(providerNameForAaguid('  bada5566-a7aa-401f-bd96-45619a55120d  '), '1Password');
});

test('every bundled name is a non-empty string and the zero AAGUID is not a key', () => {
    assert.ok(!Object.prototype.hasOwnProperty.call(AAGUID_NAMES, ZERO_AAGUID), 'zero AAGUID must not be mapped');
    for (const [k, v] of Object.entries(AAGUID_NAMES)) {
        assert.match(k, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, `${k} is a dashed lowercase UUID`);
        assert.ok(typeof v === 'string' && v.length > 0, `${k} has a non-empty name`);
    }
});
