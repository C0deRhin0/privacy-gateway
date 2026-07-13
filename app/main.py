from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from app.config import get_settings
from app.proxy import redact_payload
from app.redaction import PresidioRedactor

HOP_BY_HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host"}


async def _forward_request(request: Request, http_client: httpx.AsyncClient, upstream_base_url: str, redactor: Any) -> Response:
    payload = await request.json()
    rewritten, findings = redact_payload(payload, redactor)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    upstream_request = http_client.build_request(
        "POST",
        f"{upstream_base_url.rstrip('/')}/responses",
        headers=headers,
        json=rewritten,
        params=request.query_params,
    )
    upstream_response = await http_client.send(upstream_request, stream=bool(payload.get("stream")))

    response_headers = {k: v for k, v in upstream_response.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    response_headers["x-privacy-gateway-findings"] = str(len(findings))

    if payload.get("stream"):
        return StreamingResponse(
            upstream_response.aiter_raw(),
            status_code=upstream_response.status_code,
            headers=response_headers,
            media_type=upstream_response.headers.get("content-type"),
            background=BackgroundTask(upstream_response.aclose),
        )

    return Response(content=upstream_response.content, status_code=upstream_response.status_code, headers=response_headers, media_type=upstream_response.headers.get("content-type"))


def create_app(
    *,
    http_client: httpx.AsyncClient | None = None,
    redactor: Any | None = None,
    upstream_base_url: str | None = None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="privacy-gateway", version="0.1.0")
    app.state.http_client = http_client or httpx.AsyncClient(timeout=60)
    app.state.redactor = redactor or PresidioRedactor()
    app.state.upstream_base_url = upstream_base_url or settings.upstream_base_url

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ready"}

    @app.post("/v1/responses")
    async def responses(request: Request) -> Response:
        return await _forward_request(request, app.state.http_client, app.state.upstream_base_url, app.state.redactor)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=502)

    return app


app = create_app()
