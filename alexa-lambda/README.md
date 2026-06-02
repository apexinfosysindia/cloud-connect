# Apex Oasis — Alexa Smart Home Skill Setup

This folder contains the AWS Lambda forwarder (`index.js`) that serves as the
Smart Home skill endpoint. It contains no business logic — it forwards every
directive to the Cloud Connect portal and returns the portal's response.

## Architecture

```
Alexa Cloud ──directive──▶ AWS Lambda (index.js)
                               │  POST + X-Alexa-Forwarder-Secret
                               ▼
                 https://<portal>/api/alexa/fulfillment   ← all real logic
```

## 1. Amazon Developer Console — create the skill

1. **Alexa Developer Console → Create Skill → Smart Home model.**
2. Note the **Skill ID** (`amzn1.ask.skill.…`).
3. **Default endpoint** = the Lambda ARN from step 3 below.

## 2. Login with Amazon (LWA) security profile

Smart Home skills require an LWA security profile so the portal can push
proactive `ChangeReport` / `AddOrUpdateReport` events to the Event Gateway.

1. **developer.amazon.com → Login with Amazon → Create a Security Profile.**
2. Copy **Client ID** → portal env `ALEXA_LWA_CLIENT_ID`.
3. Copy **Client Secret** → portal env `ALEXA_LWA_CLIENT_SECRET`.
4. In the skill's **Permissions** tab, enable **Send Alexa Events** and link
   this security profile.

## 3. Deploy the Lambda

```bash
cd alexa-lambda
zip -r function.zip index.js
aws lambda create-function \
  --function-name apex-alexa-forwarder \
  --runtime nodejs18.x \
  --handler index.handler \
  --role <execution-role-arn> \
  --zip-file fileb://function.zip \
  --environment "Variables={FULFILLMENT_URL=https://oasis.apexinfosys.in/api/alexa/fulfillment,FORWARDER_SECRET=<random-secret>}"
```

Add an **Alexa Smart Home trigger** to the Lambda, pasting the **Skill ID** from
step 1. Put the resulting Lambda ARN back into the skill's Default endpoint.

## 4. Account linking (the OAuth side the portal hosts)

In the skill's **Account Linking** config:

| Field | Value |
|---|---|
| Authorization URI | `https://oasis.apexinfosys.in/api/alexa/oauth` |
| Access Token URI | `https://oasis.apexinfosys.in/api/alexa/token` |
| Client ID | value of portal env `ALEXA_CLIENT_ID` |
| Client Secret | value of portal env `ALEXA_CLIENT_SECRET` |
| Scope | `alexa::smart_home` |

The portal validates the redirect URI host against `ALEXA_REDIRECT_URI_HOSTS`
(defaults to `pitangui.amazon.com,layla.amazon.com,alexa.amazon.co.jp`).

## 5. Portal environment variables

```
ALEXA_CLIENT_ID=...              # account-linking client (matches skill config)
ALEXA_CLIENT_SECRET=...
ALEXA_LWA_CLIENT_ID=...          # LWA security profile (step 2)
ALEXA_LWA_CLIENT_SECRET=...
ALEXA_LWA_TOKEN_ENC_KEY=...      # 32-byte key, hex (64 chars) or base64 — REQUIRED
ALEXA_EVENT_GATEWAY_URL=https://api.amazonalexa.com/v3/events   # default
ALEXA_REPORT_STATE_ENABLED=1
```

Generate the encryption key once:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 6. MVP scope

This first cut supports: account linking, `Alexa.Discovery`,
`Alexa.PowerController` (on/off), `Alexa.BrightnessController`, and
`Alexa.ColorController` / `Alexa.ColorTemperatureController` for lights.
Fans, locks, thermostats, covers, sensors, and scenes are follow-ups.
