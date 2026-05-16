# First-time private Alexa skill bring-up

This is the linear checklist for standing up a fresh Alexa Smart Home
skill that talks to ApexOS Cloud Connect. It is meant to be followed
top-to-bottom on the first deploy of a new environment (staging,
production, or a developer's personal sandbox).

The codebase pieces — the OAuth endpoints (`routes/alexa-oauth.js`),
the smart-home dispatcher (`routes/alexa-smarthome.js`), the LWA token
store (`lib/alexa/core.js`), the proactive event gateway
(`lib/alexa/event-gateway.js`), the forwarder Lambda
(`lambda/alexa-forwarder/index.mjs`), and the SAM template
(`infra/alexa-lambda/template.yaml`) — are all already done. What's
left is configuration in three external consoles plus a manual smoke
test. Do these steps in order; later steps depend on identifiers
produced by earlier ones.

> **Why this is a separate document from the Lambda README.** The
> README covers `sam deploy` mechanics that you'll repeat dozens of
> times. This doc covers one-time wiring you'll touch maybe twice in
> the lifetime of an environment. Mixing them encourages copy-paste
> mistakes — and the wiring mistakes here (wrong region, wrong grant
> type, missing `alexa::events:write` permission) are exactly the ones
> that produce silent breakage rather than loud errors. Keep them apart.

---

## 0. Prerequisites

You'll need:

- **An Amazon account** that will own the skill. For production this
  should be a shared/team account, not a personal one — losing access
  to the owner means losing the skill.
- **An AWS account** with permission to deploy the SAM stack (see
  `infra/alexa-lambda/README.md`).
- **A live Cloud Connect deployment** at a public HTTPS URL (e.g.
  `https://cloud.apexinfosys.in`). Account linking will not work over plain
  HTTP, and Amazon will not accept self-signed certs.
- **Cloud Connect environment variables** ready to set:
  - `ALEXA_LWA_TOKEN_ENC_KEY` — 32 bytes hex-encoded (64 hex chars);
    generate with `openssl rand -hex 32`. Must be hex, not base64 —
    `lib/alexa/crypto.js` does `Buffer.from(raw, 'hex')` at boot and
    refuses to start if the result isn't exactly 32 bytes. Once set,
    do not change it without forcing every linked user to re-link.
  - `ALEXA_LWA_CLIENT_ID` and `ALEXA_LWA_CLIENT_SECRET` — populated
    in step 2.
  - `ALEXA_OAUTH_CLIENT_ID` and `ALEXA_OAUTH_CLIENT_SECRET` —
    populated in step 3. These are *separate* from the LWA pair; LWA
    is what Cloud Connect uses to call Amazon's Event Gateway, the
    OAuth pair is what Amazon uses to call our `/api/alexa/token`
    endpoint.

If any of these are missing, stop and get them first. The flow does
not gracefully degrade.

---

## 1. Pick the region — and pick it once

Alexa skills are region-locked. Decide upfront based on where your
users live:

| User base                     | Skill region            | AWS Lambda region |
|-------------------------------|-------------------------|-------------------|
| North America                 | English (US/CA)         | `us-east-1`       |
| **India / Europe (default)**  | English (UK/IN), Hindi  | `eu-west-1`       |
| Japan / Australia             | Japanese, English (AU)  | `us-west-2`       |

Write the chosen region down. Every following step has a region field;
they all must match. Mixing regions is the single most common
bring-up failure — the deploy succeeds, the skill links, but the
Lambda is never invoked because Alexa routes to a region where it
doesn't exist.

For ApexOS production, the answer is **`eu-west-1`**.

---

## 2. Create the LWA security profile (Login with Amazon)

This is the credential pair Cloud Connect uses to refresh user access
tokens against `https://api.amazon.com/auth/o2/token` so it can post
proactive ChangeReports to the Alexa Event Gateway. It is **not** the
same as the OAuth credentials Amazon uses to talk to us — that comes
later.

1. Go to <https://developer.amazon.com/loginwithamazon/console/site/lwa/overview.html>.
2. Click **Create a New Security Profile**.
3. Fill in:
   - Name: `ApexOS Cloud Connect (prod)` — adjust per environment.
   - Description: short sentence describing what it's for.
   - Privacy Notice URL: your public privacy policy URL.
4. Save. You'll see a **Client ID** (`amzn1.application-oa2-client.<hex>`)
   and a **Client Secret**. Copy both.
5. Set them in your Cloud Connect environment:
   ```sh
   ALEXA_LWA_CLIENT_ID=amzn1.application-oa2-client.xxxxxxxxxxxx
   ALEXA_LWA_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```
6. Restart the Cloud Connect Express app so it picks them up.

You will return to this profile in step 4 to wire the **Allowed
Origins / Allowed Return URLs** once you know the skill ID. That's
fine — leave them blank for now.

---

## 3. Create the Alexa Smart Home skill

1. Go to <https://developer.amazon.com/alexa/console/ask>.
2. Click **Create Skill**.
3. Choose:
   - Skill name: `Apex Connect+` (or environment-specific variant).
   - Default language: matches your region (e.g. **English (IN)** for
     `eu-west-1`).
   - Choose a model: **Smart Home**. *Not* Custom. Smart Home is the
     model that gives you directive routing.
   - Hosting service: **Provision your own**. We're not using
     Alexa-hosted Lambdas — ours lives in the SAM stack.
4. Click **Create skill**. You'll land on the skill's main page.
5. Copy the **Skill ID** from the top of the page (looks like
   `amzn1.ask.skill.<uuid>`). You'll need it for the SAM deploy.

Do **not** configure the endpoint or account linking yet — the
endpoint needs the Lambda ARN (step 5) and account linking needs
both the OAuth credentials (step 4) and the skill itself to exist.

---

## 4. Configure account linking

Account linking is how Amazon obtains the bearer token that gets
attached to every directive. Cloud Connect implements the OAuth 2.0
auth-code grant on `/api/alexa/oauth` (authorize) and
`/api/alexa/token` (token exchange + refresh).

In the skill console, open **Account Linking** in the left nav and
fill in:

| Field                                  | Value                                                            |
|----------------------------------------|------------------------------------------------------------------|
| Do you allow users to create...        | **No** (we already gate on a logged-in portal session)           |
| Authorization URI                      | `https://cloud.apexinfosys.in/api/alexa/oauth`                   |
| Access Token URI                       | `https://cloud.apexinfosys.in/api/alexa/token`                   |
| Client ID                              | Generate a long random string (UUID is fine). Save it.           |
| Client Secret                          | Generate another long random string. Save it.                    |
| Client Authentication Scheme           | **HTTP Basic** (matches `routes/alexa-oauth.js`)                 |
| Scope (add one)                        | `smart_home` (the value isn't checked, but Amazon requires one)  |
| Domain List                            | `cloud.apexinfosys.in`                                           |
| Default Access Token Expiration Time   | `3600` (matches our token TTL)                                   |
| Reciprocal Access Token URL            | leave blank                                                      |

Set the OAuth pair on Cloud Connect:

```sh
ALEXA_OAUTH_CLIENT_ID=<the Client ID you just generated>
ALEXA_OAUTH_CLIENT_SECRET=<the Client Secret you just generated>
```

Restart the Express app.

At the bottom of the page, Amazon shows three **Alexa Redirect URLs**
(one per region). Copy all three. Go back to your LWA security
profile from step 2, click its gear → **Web Settings**, and paste
those URLs into **Allowed Return URLs**. Also add
`https://cloud.apexinfosys.in` to **Allowed Origins**. Save.

---

## 5. Deploy the Lambda and wire the endpoint

Now that you have the skill ID, deploy the forwarder Lambda. Follow
`infra/alexa-lambda/README.md` — the only field you need from this doc
is the skill ID from step 3 and the region from step 1.

After `sam deploy --guided` finishes, grab the function ARN from the
stack outputs (the README shows the `aws cloudformation describe-stacks`
incantation).

Back in the skill console, open **Smart Home** in the left nav:

1. **Default endpoint**: paste the Lambda ARN.
2. Optionally fill in region-specific endpoints if you're shipping to
   multiple regions; for a single-region deploy the default is enough.
3. Save.

---

## 6. Enable Send Alexa Events permission

This is the easiest step to forget. Without it, proactive
ChangeReports from `lib/alexa/event-gateway.js` will be rejected by
the Event Gateway with a generic 403, and "voice control works but the
Alexa app shows stale state" becomes the support ticket of the week.

1. In the skill console, open **Permissions** in the left nav.
2. Toggle **Send Alexa Events** to **on**.
3. Copy the **Alexa Client ID** and **Alexa Client Secret** that
   appear. These are not the same as the OAuth pair from step 4 —
   they're the credentials the AcceptGrant code path exchanges for an
   LWA refresh token on first link.
4. These values are the same `ALEXA_LWA_CLIENT_ID` /
   `ALEXA_LWA_CLIENT_SECRET` you set in step 2 if you reused the
   security profile, which is the common case. If they differ, update
   the env vars and restart.

---

## 7. Install the apex-cloud-link addon on real Home Assistant

The forwarder Lambda only knows how to POST to Cloud Connect. The
addon is what actually executes the directive on the customer's HA
instance. Without it installed, Discovery returns an empty endpoints
list and nothing else works.

1. On the target HA instance, install the **apex-cloud-link** addon
   from the ApexOS addon repository (separate repo).
2. Configure it with the device's Cloud Connect access token (issued
   when the device first registered — same token the Google Home
   addon uses).
3. Start the addon. Confirm in its logs that it has called
   `POST /api/internal/devices/alexa/entities/sync` at least once.
4. In Cloud Connect, run a quick sanity check:
   ```sh
   sqlite3 /path/to/cloud-connect.db \
     "SELECT entity_id, display_name, exposed FROM alexa_entities WHERE user_id = <id> LIMIT 20;"
   ```
   You should see the addon's filtered entity list, all with
   `exposed = 1`.

---

## 8. Link the skill from the Alexa app

1. Open the Alexa mobile app while logged in as the test user.
2. **More → Skills & Games → Your Skills → Dev**. Your private skill
   is listed under Dev because it isn't published.
3. Tap **Enable to Use**. The browser opens
   `https://cloud.apexinfosys.in/api/alexa/oauth?...`.
4. Log in with the Cloud Connect portal credentials of the test user.
   You should see a brief "Linking..." page, then the Alexa app
   reports success.
5. Tap **Discover Devices**. After ~20 s the entities you exposed in
   step 7 appear.

If linking fails, check Cloud Connect logs for `routes/alexa-oauth.js`
errors first — invalid `client_id` and mismatched `redirect_uri` are
the usual culprits, and both come from copy-paste mistakes in step 4.
The v1 post-mortem flagged that AcceptGrant failures used to be
silently swallowed; the v2 code path throws loudly, but only into the
Lambda logs (`sam logs --tail`), not the user-facing error page.

### Admin diagnostic endpoints (use these during smoke testing)

Two admin-only endpoints exist specifically for Phase 9 bring-up.
Both require an admin session token (the bcrypt-gated one used by the
admin UI, not the static env-var token).

**`GET /api/admin/alexa/health`** — aggregate counters for proactive
ChangeReport delivery since the last Cloud Connect restart. Returns
`{ available, startedAt, queueDepth, counters: { ok, gateway_error,
unlinked, lwa_refresh_failed, network_error, no_properties, ... } }`
with `firstAt`/`lastAt` per reason. The signal you want during smoke
testing:

  - voice command works → expect `counters.ok` to climb
  - state stays stale in Alexa app → check `gateway_error` (usually
    means the Send Alexa Events permission from step 6 was forgotten)
  - one user broken, others fine → check `unlinked` /
    `lwa_refresh_failed` for that user specifically (they need to
    re-link from the Alexa app)

**`GET /api/admin/alexa/users/:id/preview-change-report?entity_id=light.kitchen`**
— dry-run that returns the exact ChangeReport envelope we'd have
posted, without actually posting and without minting a real LWA
access token (the bearer in the response is a fixed placeholder
string, safe to paste into a ticket). Use this when:

  - Discovery returns the entity but voice control reports it as
    "not responding" — paste the envelope into the Alexa Smart Home
    schema validator and look for malformed `endpointId` (must not
    contain dots), missing capability properties, or wrong namespace.
  - You want to confirm what *would* be sent for an out-of-scope
    domain (returns 422 `no_reportable_properties`, which means
    Phase 10 hasn't shipped that domain yet — not a bug).

The preview endpoint deliberately does not increment the health
counters or trigger an LWA refresh, so an operator can hammer it
during debugging without side effects on the live token state.

**`POST /api/admin/alexa/users/:id/commands/:cmd_id/replay`** —
re-fire a queue row that finished in a terminal state (`failed`,
`expired`, or `completed`). Inserts a *new* `alexa_command_queue`
row with the same `(user_id, device_id, entity_id, action, payload)`
and `status='pending'`; the addon picks it up via its normal
`/commands/poll` cycle. The original row is left untouched so the
audit trail is preserved.

  - 409 `command_in_flight` if the source row is `pending` or
    `dispatched` — replay during execution would risk double-firing
    a non-idempotent action (lock, scene). Wait for the original to
    settle first.
  - 404 `command_not_found` is returned for both "ID doesn't exist"
    and "ID belongs to a different user" — same response shape so
    cross-user enumeration isn't possible.

Use this when section 9 of the smoke test produces a single
intermittent failure (network blip, addon hiccup) rather than a
systemic problem — replaying is the right primitive to recover one
device without making the customer issue the voice command again.

---

## 9. Manual end-to-end smoke test

This is the gate before declaring Phase 9 done.

1. Pick one switch and one light from the discovered entities.
2. **Voice tests**:
   - "Alexa, turn on the kitchen light" → light turns on within 2 s.
   - "Alexa, turn off the kitchen light" → light turns off within 2 s.
   - "Alexa, set the kitchen light to 50 percent" → brightness lands
     at ~50% (only if the light supports brightness).
3. **State sync test**: physically toggle the switch at the wall.
   Within 2 s the Alexa app's device tile should reflect the new
   state. If it doesn't, the Event Gateway path is broken — check
   Cloud Connect logs for `event-gateway` warnings.
4. **App control test**: open the device tile in the Alexa app, tap
   the toggle. The light should respond.

If all four pass, the bring-up is complete and Phase 10 (extending the
domain coverage) is unblocked. If any of them fail, **do not proceed
to Phase 10** — the Walking Skeleton premise is that we don't pile
new mappings on an unverified pipeline.

---

## 10. What to record after a successful bring-up

For ops continuity, capture in your environment's secrets manager:

- The Skill ID (`amzn1.ask.skill.<uuid>`).
- The LWA security profile Client ID + Secret.
- The OAuth Client ID + Secret you generated for account linking.
- The Lambda ARN and region.
- The CloudFormation stack name (`apexos-alexa-forwarder-prod` by
  default).
- Which Amazon account owns the skill, and who has admin access.

Without these, rotating any one credential later turns into an
archaeology project.
