# privacy-gateway

A privacy-preserving, OpenAI-compatible proxy that redacts PII and related sensitive
values before requests reach an upstream provider.

## Public repository vs. private operations

This repository contains portable source, tests, public templates, and fictional
examples only. It does **not** document or control any operator's running deployment.
Do not copy a production service unit, environment file, contextual map, endpoint,
key, certificate, token, or organization-specific configuration into this repository.

Public portability artifacts:

- `.env.example` — safe local configuration template
- `examples/context-map.example.json` — fictional contextual-map schema example
- `deploy/systemd/privacy-gateway-portable.service` — portable systemd template

The existing operator-specific systemd units are retained locally in a live checkout but
are deliberately ignored and untracked for public publishing. They are not installation
templates. Do not edit active units or manage services from a source checkout without an
approved operational change process.

## Capabilities and routes

### Ordinary redaction route

| Route | Purpose |
| --- | --- |
| `GET /health` | Liveness check. |
| `GET /readyz` | Base gateway readiness check. |
| `POST /v1/responses` | OpenAI Responses-compatible forwarding with request-side secret and generic-PII redaction. |

The ordinary route does not load or apply a contextual map. This keeps a deployment's
contextual policy isolated from general traffic.

### Optional contextual routes

When a private contextual map is configured and the route's token policy is satisfied,
these routes apply additional route-scoped pseudonymization. They fail closed with `503`
if the required map/key policy is unavailable.

| Route | Purpose |
| --- | --- |
| `GET /mac/readyz` | Contextual-route readiness check. |
| `POST /mac/v1/responses` | Contextual protection for OpenAI Responses-compatible requests. |
| `POST /mac/v1/messages` | Contextual protection for Messages-style requests. |
| `POST /mac/anthropic/v1/messages` | Contextual protection for native Anthropic Messages-compatible requests. |

The contextual Messages routes are forwarded upstream using the Messages wire endpoint;
route selection is based on the actual HTTP path rather than a model name.

### Privacy processing behavior

For contextual routes, the outbound request-copy processing order is:

```text
secret redaction → contextual longest-match pseudonymization → generic PII redaction → upstream provider
```

The gateway leaves local source data alone and transforms only the provider-bound request
copy. It removes internal `x-privacy-gateway-*` control headers before forwarding.

Contextual replacements use opaque, request-scoped tokens. On the return path, the gateway
restores only tokens emitted for the current request, then applies output DLP to user-visible
text, including ordinary JSON responses, streaming SSE responses, and refusal text. Unknown,
malformed, stale, or provider-invented tokens remain literal rather than being restored.

Supported contextual modes are `BASE`, `STANDARD` (the default), and `STRICT`. Select one
per request with `x-privacy-gateway-pseudonymization-mode`; use a private conversation ID or
scope header only when the calling application needs stable request scope.

## Local setup

Requires Python 3.11 or newer.

```bash
git clone <repository-url> privacy-gateway
cd privacy-gateway
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
```

Edit the local `.env` with an upstream URL reachable from your machine. Keep it out of
version control. The application reads environment variables directly, so load it before
running commands:

```bash
set -a; . ./.env; set +a
```

## Configuration

Required configuration is minimal:

- `PRIVACY_GATEWAY_UPSTREAM_BASE_URL` — an OpenAI-compatible upstream base URL
- `PRIVACY_GATEWAY_HOST` and `PRIVACY_GATEWAY_PORT` — local listener address
- `PRIVACY_GATEWAY_STRICT` — enables strict redaction when `true`

For contextual pseudonymization, copy `examples/context-map.example.json` to a private
path outside this checkout and configure `PRIVACY_GATEWAY_CONTEXT_MAP_PATH`. Its values
must remain fictional in `examples/`; real maps reveal sensitive business context and
must never be committed, published, or sent to an upstream provider. Set
`PRIVACY_GATEWAY_PSEUDONYMIZATION_TOKEN_KEY` to a stable, deployment-specific,
high-entropy secret and never publish it.

## Run locally

```bash
. .venv/bin/activate
set -a; . ./.env; set +a
uvicorn app.main:app --host "$PRIVACY_GATEWAY_HOST" --port "$PRIVACY_GATEWAY_PORT"
```

## Test, lint, and compile

```bash
. .venv/bin/activate
pytest tests -v
ruff check .
python3 -m compileall app scripts
```

## Install with systemd

1. Create a dedicated, unprivileged service account and install this repository at a
   host-specific path, such as `/opt/privacy-gateway`.
2. Create its virtual environment and install the application and dependencies.
3. Copy `deploy/systemd/privacy-gateway-portable.service` to a private staging location.
   Replace `CHANGE_ME_SERVICE_USER`, `CHANGE_ME_SERVICE_GROUP`, and every
   `/opt/privacy-gateway` path with target-host values.
4. Create `/etc/privacy-gateway/privacy-gateway.env`, restrict it to the service user,
   and set the required `PRIVACY_GATEWAY_*` variables. Do not store this file in the
   checkout or publish real endpoints, maps, keys, or tokens.
5. Have an authorized operator install the reviewed unit, then run `systemctl daemon-reload`
   and enable/start the newly installed service according to local change procedures.

The systemd template deliberately reads the upstream and other deployment values from a
private environment file rather than embedding them in the unit.

## Security and publishing checklist

Before publishing a fork or patch, confirm it contains no:

- real contextual maps or organization/entity aliases
- API keys, tokens, passwords, private endpoints, or IP addresses
- private keys, certificates, or keystores
- local `.env` files, runtime logs, coverage data, or process artifacts

`.gitignore` reduces accidental additions but cannot remove already tracked secrets.
Review `git status` and repository history before publishing. If a secret was ever
committed, revoke or rotate it using the relevant operational process.
