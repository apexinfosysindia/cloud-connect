# Alexa Smart Home Lambda Forwarder

Thin Lambda that Alexa Smart Home invokes; it forwards every directive to
Cloud Connect's `/api/alexa/smarthome` endpoint and returns the response
verbatim. Cloud Connect does all the real work (Discovery, ReportState,
AcceptGrant, per-interface directives).

## Deploy

1. Runtime: **Node.js 20.x** (uses global `fetch` and `node:crypto`).
2. Handler: `index.handler`
3. Timeout: **8 seconds** (Alexa's total budget is 8s; do not exceed).
4. Memory: 128 MB is sufficient.
5. Zip and upload:
   ```sh
   cd lambda/alexa-forwarder
   zip -r ../alexa-forwarder.zip index.mjs
   aws lambda create-function \
     --function-name cloud-connect-alexa-forwarder \
     --runtime nodejs20.x \
     --role arn:aws:iam::<ACCOUNT>:role/alexa-forwarder-role \
     --handler index.handler \
     --timeout 8 \
     --zip-file fileb://../alexa-forwarder.zip
   ```
6. Environment variables:
   - `CLOUD_CONNECT_URL` — e.g. `https://cloud.apexinfosys.in/api/alexa/smarthome`
   - `FORWARDER_SECRET` — must match `ALEXA_FORWARDER_SHARED_SECRET` on the server
7. Trigger: add an **Alexa Smart Home** trigger and paste your skill ID
   (`amzn1.ask.skill.…`). Must be in `us-east-1`, `eu-west-1`, or `us-west-2`
   per Alexa Smart Home region requirements.

## Error handling

Non-2xx responses from Cloud Connect and network errors are translated into
`Alexa.ErrorResponse` envelopes with `type: INTERNAL_ERROR` so the skill
surface always returns a well-formed event (Alexa otherwise logs the raw
crash as an opaque skill error).
