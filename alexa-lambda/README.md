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
ALEXA_EVENT_GATEWAY_URL=https://api.eu.amazonalexa.com/v3/events   # EU skills
# US skills use https://api.amazonalexa.com/v3/events instead. The host MUST
# match the skill's region, or proactive ChangeReport/AddOrUpdateReport calls
# fail. The Lambda region (step 3) must match too.
ALEXA_REPORT_STATE_ENABLED=1
ALEXA_FORWARDER_SECRET=...       # OPTIONAL; must equal the Lambda's FORWARDER_SECRET
```

> **Forwarder secret (defense in depth).** The Lambda always sends the
> `X-Alexa-Forwarder-Secret` header. The portal only *enforces* it when
> `ALEXA_FORWARDER_SECRET` is set in the portal env — then any directive whose
> header doesn't match (e.g. someone POSTing to `/api/alexa/fulfillment`
> directly, bypassing the Lambda) is rejected. Leave both unset to disable the
> check; the per-directive bearer token is the primary auth either way. If you
> set it, the Lambda's `FORWARDER_SECRET` and the portal's
> `ALEXA_FORWARDER_SECRET` must be byte-identical.

Generate the encryption key once:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 6. Domain coverage

The skill exposes the same entity domains as the Google Assistant
bridge (minus those Alexa's custom-skill API cannot represent):

| Domain(s) | Alexa interface(s) |
|---|---|
| light | Power + Brightness + Color + ColorTemperature |
| switch, outlet, input_boolean, automation, group | PowerController |
| scene, script, button, input_button | SceneController |
| lock | LockController |
| fan | Power + RangeController (speed) + ToggleController (oscillate) + ModeController (preset/direction) |
| cover, valve | RangeController (position/tilt) or ModeController (garage/discrete) + open/close semantics |
| sensor (temperature/humidity) | TemperatureSensor / HumiditySensor |
| binary_sensor (door/window/opening/motion/occupancy) | ContactSensor / MotionSensor |
| select, input_select | ModeController |
| humidifier | Power + RangeController (humidity) + ModeController |
| water_heater | Power + ThermostatController (single setpoint) + TemperatureSensor |
| climate | ThermostatController (dual setpoint + modes) + TemperatureSensor + ModeController (fan/preset/swing) |
| vacuum, lawn_mower | Power + ModeController (+ vacuum suction) |
| media_player | Power + PlaybackController + Speaker + InputController |
| alarm_control_panel | SecurityPanelController (PIN required to disarm when configured) |

**Excluded (no Alexa custom-skill equivalent):** air-quality sensors
(pm25/pm10/co2/co/voc/aqi) and smoke/CO/gas/leak binary_sensors — these are
dropped from Discovery rather than exposed as broken endpoints. **Deferred:**
`camera` (CameraStreamController needs a public media endpoint the frp tunnel
doesn't provide) and `event` doorbells (DoorbellEventSource needs a real-time
push path the snapshot poll can't supply).

