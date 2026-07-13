# privacy-gateway

Privacy-preserving OpenAI-compatible proxy that sits in front of Headroom and redacts PII and closely related sensitive values before prompts leave the machine.

## Architecture

```text
Hermes -> privacy-gateway -> Headroom -> upstream provider
```

## Isolation guardrails

This project is intentionally isolated from Hermes and Headroom:

- all application logic lives in this repo
- Hermes integration is limited to `HERMES_CODEX_BASE_URL` override changes only
- Headroom integration is limited to upstream forwarding only
- removal is operational rollback, not source-code surgery
- default-profile cutover should remain prepared-but-inactive until canary evidence is accepted

## Current deployment state

- `privacy-gateway.service`: installed and running on `127.0.0.1:14000`
- `researcher` profile: **live canary enabled** via user-service drop-in
- `default` profile: **prepared only**, not cut over yet

## Implemented scope

- `GET /health`
- `GET /readyz`
- `POST /v1/responses`
- request-side redaction for current and near-future payload variants
- streaming passthrough to Headroom
- deployable systemd unit
- rollback runbook in `docs/ROLLBACK.md`

## Redaction coverage

Current redaction focuses on PII and nearby high-sensitivity values:

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`
- `CREDIT_CARD`
- `US_SSN`
- `IP_ADDRESS`
- `JWT_TOKEN`
- `API_SECRET`

Current payload extractor logic redacts text in these common request shapes:

- `instructions`
- `prompt`
- root `input` string values
- `input[*].content[*].text`
- `messages[*].content` string values
- `messages[*].content[*].text` text-part arrays
- other known text-bearing keys such as `query`, `message`, `summary`, `context`, `developer`, `system`, and `user_input`

Non-text protocol fields like `model`, `id`, `role`, `type`, `provider`, and tool identifiers are intentionally not rewritten.

## False-positive / false-negative tuning

Current tuning choices:

- phone recognition requires 10-15 digits to avoid masking short room/build numbers
- credit-card masking requires a Luhn-valid 13-19 digit candidate
- IP masking validates each octet range
- generic API secret matching is prefix-based and length-gated to avoid sweeping ordinary prose
- partially masked secret fragments such as `ghp_abcd1234...wxyz9876` are also redacted to avoid leaking support-log style token fragments

This keeps the proxy conservative for production canaries while still catching common sensitive material.

## Canary / rollout model

1. run unit + adversarial tests locally
2. verify `privacy-gateway.service` health on `127.0.0.1:14000`
3. verify one-shot Hermes CLI with temporary `HERMES_CODEX_BASE_URL`
4. enable **researcher** canary first
5. verify researcher service env/runtime
6. only then consider default-profile cutover

## Local development

```bash
cd /srv/workspaces/Github/privacy-gateway/codebase
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest tests -v
ruff check .
python3 -m compileall app scripts
```

## Run locally

```bash
cd /srv/workspaces/Github/privacy-gateway/codebase
. .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 14000
```

## Installed systemd artifacts

Repo templates:

- `deploy/systemd/privacy-gateway.service`
- `deploy/systemd/hermes-gateway-default-zz-privacy-gateway.conf`
- `deploy/systemd/hermes-gateway-researcher-zz-privacy-gateway.conf`

Host state:

- active service: `/etc/systemd/system/privacy-gateway.service`
- prepared default drop-in: `/etc/systemd/system/hermes-gateway.service.d/zz-privacy-gateway.conf.prepared`
- active researcher canary: `~/.config/systemd/user/hermes-gateway-researcher.service.d/zz-privacy-gateway.conf`

## Environment

See `.env.example`.

Important variables:

- `PRIVACY_GATEWAY_UPSTREAM_BASE_URL` default: `http://127.0.0.1:18787/v1`
- `PRIVACY_GATEWAY_HOST` default: `127.0.0.1`
- `PRIVACY_GATEWAY_PORT` default: `14000`

## Verification commands

```bash
cd /srv/workspaces/Github/privacy-gateway/codebase
. .venv/bin/activate
pytest tests -v
ruff check .
python3 -m compileall app scripts
python scripts/smoke_responses.py
curl http://127.0.0.1:14000/health
```

## Rollback

See `docs/ROLLBACK.md`.

Short version:

1. remove the active profile drop-in
2. restart the affected Hermes gateway service
3. verify traffic returns directly to Headroom
4. disable/remove `privacy-gateway.service` if the project is no longer wanted
