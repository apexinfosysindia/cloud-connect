# Deploying the Alexa forwarder Lambda

This directory contains the AWS SAM template that deploys
`lambda/alexa-forwarder/index.mjs` as an AWS Lambda function bound to a
single Alexa Smart Home skill.

The Lambda is a stateless network hop: every dispatch decision is made by
the Cloud Connect Express app at `routes/alexa-smarthome.js`. Treat this
deploy as low-stakes plumbing — there is no business logic to roll back.

## Prerequisites

1. **AWS account + IAM credentials** with permission to create CloudFormation
   stacks and Lambda functions. The deploying principal needs at least the
   AWS managed `AWSCloudFormationFullAccess` and the SAM-generated
   `AWSLambda_FullAccess`. Production deploys should narrow these.
2. **The `aws-sam-cli`** (version ≥ 1.100). On macOS:
   `brew install aws-sam-cli`.
3. **An Alexa Smart Home skill ID** from the Amazon Developer Console.
   Create the skill first (see `docs/alexa/private-skill-bringup.md`), grab
   the `amzn1.ask.skill.<uuid>` value, then come back here.
4. **The Cloud Connect origin URL** the Lambda should forward to. For the
   primary environment this is `https://cloud.apexinfosys.in`. The origin must
   already be live; the SAM template does not provision any public-facing
   infrastructure.

## Region selection — important

Alexa skills are region-locked to a small set of Lambda regions:

| Skill region | Required Lambda region |
|--------------|------------------------|
| North America (English) | `us-east-1` |
| Europe / India (English / Hindi) | `eu-west-1` |
| Far East (Japanese / English-AU) | `us-west-2` |

The skill's region is decided when you create it in the developer console;
the Lambda must live in the matching AWS region. Deploying the stack to the
wrong region will succeed but the trigger will silently never fire because
Alexa won't be able to invoke it.

For ApexOS's primary user base (India), use `eu-west-1`.

## First-time deploy

```sh
cd infra/alexa-lambda

sam deploy \
    --guided \
    --template-file template.yaml \
    --stack-name apexos-alexa-forwarder-prod \
    --region eu-west-1 \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides \
        CloudConnectOrigin=https://cloud.apexinfosys.in \
        AlexaSkillId=amzn1.ask.skill.REPLACE-ME \
        Stage=prod
```

`--guided` walks you through saving the parameters into
`samconfig.toml` so subsequent deploys can drop the flags. **Do not commit
`samconfig.toml`** — it's already in `.gitignore` (add it if not).

## Subsequent deploys

```sh
cd infra/alexa-lambda
sam deploy
```

Picks up the saved config. Use this whenever `lambda/alexa-forwarder/index.mjs`
changes.

## Verifying the deploy

1. Grab the function ARN from the stack outputs:
   ```sh
   aws cloudformation describe-stacks \
       --stack-name apexos-alexa-forwarder-prod \
       --query 'Stacks[0].Outputs[?OutputKey==`FunctionArn`].OutputValue' \
       --output text \
       --region eu-west-1
   ```
2. Tail the logs (in another terminal):
   ```sh
   sam logs --stack-name apexos-alexa-forwarder-prod --region eu-west-1 --tail
   ```
3. From the Alexa app, attempt to link the Apex Connect+ skill. You should
   see exactly one invocation per directive (Discovery, AcceptGrant, then
   per voice command).

## Smoke-testing without Alexa

The Lambda accepts a raw directive event. To verify the forwarder is
reachable and the env vars are right, invoke it locally with a fixture:

```sh
sam local invoke AlexaForwarderFunction \
    --event events/discovery.json \
    --env-vars env.json
```

You'll need to author `events/discovery.json` (a recorded Alexa Discovery
directive — Alexa's own developer console can generate one) and `env.json`:

```json
{
    "AlexaForwarderFunction": {
        "CLOUD_CONNECT_ORIGIN": "https://cloud.apexinfosys.in",
        "CLOUD_CONNECT_PATH": "/api/alexa/smarthome"
    }
}
```

A successful invocation returns a JSON object with
`event.header.namespace == "Alexa.Discovery"` and an `endpoints` array.
Anything else (notably an `Alexa/ErrorResponse` with type
`INVALID_AUTHORIZATION_CREDENTIAL`) means the test bearer token isn't
valid — that's expected from a hand-rolled fixture. Use a real linked
skill for the round-trip test.

## Rollback

CloudFormation rolls back failed stack updates automatically. To roll back
a successful but bad deploy:

```sh
# Find the previous version
aws lambda list-versions-by-function \
    --function-name apexos-alexa-forwarder-prod \
    --region eu-west-1

# Re-publish the previous version as $LATEST by redeploying the older
# checkout:
git checkout <previous-good-sha> -- ../../lambda/alexa-forwarder/
sam deploy
git checkout HEAD -- ../../lambda/alexa-forwarder/
```

There is no per-Lambda version pinning here on purpose — the trigger always
points at `$LATEST`. If you need versioned aliases (blue/green), add a
`AutoPublishAlias: live` block to the function in `template.yaml` and a
`DeploymentPreference` block. We don't need this until traffic justifies it.

## Tearing it down

```sh
aws cloudformation delete-stack \
    --stack-name apexos-alexa-forwarder-prod \
    --region eu-west-1
```

Note: deleting the stack does NOT delete the skill. Skills live in the
Amazon Developer Console and are managed separately.

## Cost expectations

For a single-skill private deployment with a few dozen voice commands per
day:

- Lambda invocations: < 10k/month → free tier covers it (1M req/mo free).
- Lambda compute: ~ 200 ms × 128 MB per invocation ≈ negligible.
- CloudWatch logs: ~ 1 KB per directive, 7-day retention → effectively zero.

Expect < $0.10/month per skill at this volume. If costs spike, the most
likely cause is a misconfigured ChangeReport loop (Phase 11) hammering the
event gateway and triggering a corresponding flood of return-trip
directives — check `sam logs` for invocation cadence first.
