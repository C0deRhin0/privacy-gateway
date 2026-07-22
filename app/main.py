from __future__ import annotations

import json
import logging
import re
import secrets
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.config import get_settings
from app.proxy import redact_payload, redact_payload_pii, redact_payload_secrets, rehydrate_response_text, transform_payload_text
from app.pseudonymization import ContextMapLoader, ContextualPseudonymizer, PseudonymizationMode, PseudonymizationUnavailable
from app.redaction import PresidioRedactor

HOP_BY_HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host"}
INTERNAL_HEADER_PREFIX = "x-privacy-gateway-"
MAC_RESPONSES_ROUTE = "/mac/v1/responses"
MAC_MESSAGES_ROUTE = "/mac/v1/messages"
MAC_ANTHROPIC_MESSAGES_ROUTE = "/mac/anthropic/v1/messages"
SSE_FRAME_BOUNDARY = re.compile(br"\r?\n\r?\n")
MAX_SSE_FRAME_BUFFER_BYTES = 64 * 1024

logger = logging.getLogger("uvicorn.error")


class _StreamingRehydrator:
    """Rehydrate request-local tokens while retaining only a possible token suffix."""

    def __init__(self, token_aliases: dict[str, str], redactor: Any):
        self._token_aliases = token_aliases
        self._redactor = redactor
        self._tokens = tuple(token_aliases)
        self._pending_deltas: dict[str, str] = {}
        self.matched_active_tokens = 0

    def _rehydrate(self, text: str) -> str:
        self.matched_active_tokens += sum(text.count(token) for token in self._tokens)
        return rehydrate_response_text({"output_text": text}, self._token_aliases, self._redactor)["output_text"]

    def _trailing_token_prefix(self, text: str) -> str:
        longest_prefix = ""
        for token in self._tokens:
            max_length = min(len(token) - 1, len(text))
            for length in range(max_length, len(longest_prefix), -1):
                if text.endswith(token[:length]):
                    longest_prefix = token[:length]
                    break
        return longest_prefix

    def rehydrate_delta(self, delta: str, *, stream: str) -> str:
        text = self._pending_deltas.get(stream, "") + delta
        pending_delta = self._trailing_token_prefix(text)
        self._pending_deltas[stream] = pending_delta
        if pending_delta:
            text = text[: -len(pending_delta)]
        return self._rehydrate(text)

    def rehydrate_text(self, text: str) -> str:
        return self._rehydrate(text)

    def rehydrate_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        return rehydrate_response_text(payload, self._token_aliases, self._redactor)


def _rehydrate_sse_frame(frame: bytes, rehydrator: _StreamingRehydrator) -> bytes:
    try:
        lines = frame.decode("utf-8").splitlines(keepends=True)
        for index, line in enumerate(lines):
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            event = json.loads(data)
            if event.get("type") == "response.output_text.delta" and isinstance(event.get("delta"), str):
                event["delta"] = rehydrator.rehydrate_delta(event["delta"], stream="output_text")
            elif event.get("type") == "response.refusal.delta" and isinstance(event.get("delta"), str):
                event["delta"] = rehydrator.rehydrate_delta(event["delta"], stream="refusal")
            elif event.get("type") == "response.output_text.done" and isinstance(event.get("text"), str):
                event["text"] = rehydrator.rehydrate_text(event["text"])
            elif event.get("type") == "response.completed" and isinstance(event.get("response"), dict):
                event["response"] = rehydrator.rehydrate_payload(event["response"])
            else:
                continue
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines[index] = f"data: {json.dumps(event, separators=(',', ':'))}{newline}"
        return "".join(lines).encode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return frame


async def _rehydrate_sse_stream(source: Any, token_aliases: dict[str, str], redactor: Any):
    pending = b""
    rehydrator = _StreamingRehydrator(token_aliases, redactor)
    async for chunk in source:
        pending += chunk
        while match := SSE_FRAME_BOUNDARY.search(pending):
            frame, pending = pending[: match.end()], pending[match.end() :]
            yield _rehydrate_sse_frame(frame, rehydrator)
        if len(pending) > MAX_SSE_FRAME_BUFFER_BYTES:
            yield pending
            pending = b""
    if pending:
        yield _rehydrate_sse_frame(pending, rehydrator)
    logger.info(
        "mac_stream_rehydration_metrics active_aliases=%d matched_active_tokens=%d",
        len(token_aliases),
        rehydrator.matched_active_tokens,
    )


async def _rehydrate_sse_bytes(body: bytes, token_aliases: dict[str, str], redactor: Any) -> bytes:
    async def source():
        yield body

    return b"".join([chunk async for chunk in _rehydrate_sse_stream(source(), token_aliases, redactor)])


def _rehydrate_opaque_response_body(body: bytes, token_aliases: dict[str, str], redactor: Any) -> bytes:
    """Safe final fallback for provider protocol variants not represented as JSON/SSE."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    for token, alias in token_aliases.items():
        text = text.replace(token, alias)
    result = redactor.redact_text(text)
    return (result["text"] if isinstance(result, dict) else result.text).encode("utf-8")


async def _forward_request(
    request: Request,
    http_client: httpx.AsyncClient,
    upstream_base_url: str,
    redactor: Any,
    pseudonymizer: ContextualPseudonymizer | None = None,
    *,
    upstream_endpoint: str = "responses",
    pseudonymization_route: str | None = None,
) -> Response:
    payload = await request.json()
    if pseudonymizer:
        rewritten, findings = redact_payload_secrets(payload, redactor)
    else:
        rewritten, findings = redact_payload(payload, redactor)
    active_tokens: set[str] = set()
    rehydration_aliases: dict[str, str] = {}
    if pseudonymizer:
        try:
            mode = PseudonymizationMode(request.headers.get("x-privacy-gateway-pseudonymization-mode", "STANDARD").upper())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid pseudonymization mode") from exc
        scope = request.headers.get("x-privacy-gateway-conversation-id") or request.headers.get("x-privacy-gateway-scope") or secrets.token_urlsafe(24)

        def pseudonymize_text(text: str, _: tuple[str, ...]) -> str:
            result = pseudonymizer.pseudonymize(text, route=pseudonymization_route or request.url.path, mode=mode, scope=scope)
            active_tokens.update(result.active_tokens)
            rehydration_aliases.update(result.token_display_aliases)
            return result.text

        try:
            rewritten = transform_payload_text(rewritten, pseudonymize_text)
        except PseudonymizationUnavailable as exc:
            raise HTTPException(status_code=503, detail="contextual pseudonymization unavailable") from exc
        rewritten, pii_findings = redact_payload_pii(rewritten, redactor)
        findings.extend(pii_findings)
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and not key.lower().startswith(INTERNAL_HEADER_PREFIX)
    }
    upstream_request = http_client.build_request(
        "POST",
        f"{upstream_base_url.rstrip('/')}/{upstream_endpoint}",
        headers=headers,
        json=rewritten,
        params=request.query_params,
    )
    upstream_response = await http_client.send(upstream_request, stream=bool(payload.get("stream")))

    response_headers = {k: v for k, v in upstream_response.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    response_headers["x-privacy-gateway-findings"] = str(len(findings))
    if pseudonymizer:
        response_headers["x-privacy-gateway-pseudonyms"] = str(len(active_tokens))

    if payload.get("stream"):
        stream = upstream_response.aiter_raw()
        if pseudonymizer:
            stream = _rehydrate_sse_stream(
                stream,
                rehydration_aliases,
                redactor,
            )
        return StreamingResponse(
            stream,
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
            background=BackgroundTask(upstream_response.aclose),
        )

    content = upstream_response.content
    if pseudonymizer:
        content_type = upstream_response.headers.get("content-type", "").lower()
        looks_like_sse = "text/event-stream" in content_type or content.lstrip().startswith(b"data:")
        if looks_like_sse:
            content = await _rehydrate_sse_bytes(content, rehydration_aliases, redactor)
        else:
            try:
                response_json = upstream_response.json()
                matched_active_tokens = sum(
                    1
                    for token in rehydration_aliases
                    if token in json.dumps(response_json, separators=(",", ":"))
                )
                logger.info(
                    "mac_json_rehydration_metrics active_aliases=%d matched_active_tokens=%d",
                    len(rehydration_aliases),
                    matched_active_tokens,
                )
                content = json.dumps(rehydrate_response_text(response_json, rehydration_aliases, redactor)).encode()
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        if b"<PG:" in content:
            content = _rehydrate_opaque_response_body(content, rehydration_aliases, redactor)
    return Response(content=content, status_code=upstream_response.status_code, headers=response_headers, media_type=upstream_response.headers.get("content-type"))


def create_app(
    *,
    http_client: httpx.AsyncClient | None = None,
    redactor: Any | None = None,
    upstream_base_url: str | None = None,
    context_map_path: str | Path | None = None,
    pseudonymization_token_key: bytes | None = None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="privacy-gateway", version="0.1.0")
    app.state.http_client = http_client or httpx.AsyncClient(timeout=60)
    app.state.redactor = redactor or PresidioRedactor()
    app.state.upstream_base_url = upstream_base_url or settings.upstream_base_url
    configured_map_path = context_map_path or settings.context_map_path
    configured_token_key = pseudonymization_token_key or (
        settings.pseudonymization_token_key.encode() if settings.pseudonymization_token_key else None
    )
    app.state.pseudonymizer = None
    if configured_map_path:
        try:
            app.state.pseudonymizer = ContextualPseudonymizer(
                ContextMapLoader(configured_map_path).load(), token_key=configured_token_key
            )
        except (OSError, ValueError):
            logger.error("context_map_load_failed")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/mac/readyz")
    async def mac_readyz() -> JSONResponse:
        pseudonymizer = app.state.pseudonymizer
        if pseudonymizer is None or not pseudonymizer.is_ready_for_route(MAC_RESPONSES_ROUTE):
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.post("/v1/responses")
    async def responses(request: Request) -> Response:
        return await _forward_request(request, app.state.http_client, app.state.upstream_base_url, app.state.redactor)

    @app.post("/mac/v1/responses")
    async def mac_responses(request: Request) -> Response:
        if app.state.pseudonymizer is None or not app.state.pseudonymizer.is_ready_for_route(request.url.path):
            raise HTTPException(status_code=503, detail="contextual pseudonymization unavailable")
        return await _forward_request(
            request,
            app.state.http_client,
            app.state.upstream_base_url,
            app.state.redactor,
            app.state.pseudonymizer,
        )

    @app.post(MAC_MESSAGES_ROUTE)
    @app.post(MAC_ANTHROPIC_MESSAGES_ROUTE)
    async def mac_messages(request: Request) -> Response:
        # Anthropic Messages shares Mac's contextual map and strict request-local
        # token policy; the wire protocol determines the upstream endpoint.
        if app.state.pseudonymizer is None or not app.state.pseudonymizer.is_ready_for_route(MAC_RESPONSES_ROUTE):
            raise HTTPException(status_code=503, detail="contextual pseudonymization unavailable")
        return await _forward_request(
            request,
            app.state.http_client,
            app.state.upstream_base_url,
            app.state.redactor,
            app.state.pseudonymizer,
            upstream_endpoint="messages",
            pseudonymization_route=MAC_RESPONSES_ROUTE,
        )

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=502)

    return app


app = create_app()
