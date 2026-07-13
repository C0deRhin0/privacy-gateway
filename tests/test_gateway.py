import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.redaction import PresidioRedactor


class StubRedactor:
    def __init__(self):
        self.calls = []

    def redact_text(self, text: str):
        self.calls.append(text)
        replacements = {
            "alice@example.com": "<EMAIL_ADDRESS>",
            "+1 415 555 0124": "<PHONE_NUMBER>",
            "ghp_abcdefghijklmnopqrstuvwxyz123456": "<API_SECRET>",
        }
        redacted = text
        for old, new in replacements.items():
            redacted = redacted.replace(old, new)
        return {
            "text": redacted,
            "items": [{"entity_type": "REDACTED", "original": text, "replacement": redacted}],
        }


class AsyncSSEStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


@pytest.fixture()
def payload():
    return {
        "model": "gpt-5.4",
        "stream": False,
        "instructions": "Never expose alice@example.com",
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Contact me at alice@example.com or +1 415 555 0124"}
                ],
            }
        ],
    }


def test_health_endpoint_reports_ok():
    app = create_app(http_client=httpx.AsyncClient(), redactor=StubRedactor())
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_real_presidio_redactor_masks_sensitive_entities():
    text = (
        "Email alice@example.com, call +1 415 555 0124, use 4111 1111 1111 1111, "
        "token ghp_abcdefghijklmnopqrstuvwxyz123456, ssn 123-45-6789"
    )

    result = PresidioRedactor().redact_text(text)

    assert "<EMAIL_ADDRESS>" in result.text
    assert "<PHONE_NUMBER>" in result.text
    assert "<CREDIT_CARD>" in result.text
    assert "<API_SECRET>" in result.text
    assert "<US_SSN>" in result.text


def test_redactor_masks_partial_secret_fragments():
    text = "Example leaked token fragment ghp_abcd1234...wxyz9876 should not pass through."

    result = PresidioRedactor().redact_text(text)

    assert "ghp_abcd1234...wxyz9876" not in result.text
    assert "<API_SECRET>" in result.text


def test_redactor_avoids_common_false_positives():
    text = "Build 2026 ships in room 415 and issue 123456789 should stay visible."

    result = PresidioRedactor().redact_text(text)

    assert result.text == text
    assert result.items == []


def test_redactor_avoids_semver_datetime_and_invalid_ip_false_positives():
    text = "release v1.2.3 deadline 2026-07-08 10:30 invalid ip 999.999.999.999"

    result = PresidioRedactor().redact_text(text)

    assert result.text == text
    assert result.items == []


def test_responses_request_redacts_multiple_payload_variants(payload):
    payload["messages"] = [
        {"role": "system", "content": "Escalate to alice@example.com"},
        {"role": "user", "content": [{"type": "text", "text": "secret ghp_abcdefghijklmnopqrstuvwxyz123456"}]},
    ]
    payload["prompt"] = "phone +1 415 555 0124"
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"id": "resp_1", "status": "completed", "output": []})

    transport = httpx.MockTransport(handler)
    upstream_client = httpx.AsyncClient(transport=transport)
    redactor = StubRedactor()
    app = create_app(http_client=upstream_client, redactor=redactor, upstream_base_url="http://headroom.test/v1")
    client = TestClient(app)

    response = client.post("/v1/responses", json=payload)

    assert response.status_code == 200
    assert "Never expose alice@example.com" in redactor.calls
    assert "Contact me at alice@example.com or +1 415 555 0124" in redactor.calls
    assert captured["body"]["instructions"] == "Never expose <EMAIL_ADDRESS>"
    assert captured["body"]["input"][0]["content"][0]["text"] == "Contact me at <EMAIL_ADDRESS> or <PHONE_NUMBER>"
    assert captured["body"]["messages"][0]["content"] == "Escalate to <EMAIL_ADDRESS>"
    assert captured["body"]["messages"][1]["content"][0]["text"] == "secret <API_SECRET>"
    assert captured["body"]["prompt"] == "phone <PHONE_NUMBER>"
    assert response.headers["x-privacy-gateway-findings"] != "0"


def test_streaming_passthrough_preserves_large_sse_frames(payload):
    payload["stream"] = True
    large_frames = [
        f"data: {{\"type\":\"response.output_text.delta\",\"delta\":\"chunk-{index:04d}-{'x' * 512}\"}}\n\n".encode()
        for index in range(40)
    ]
    large_frames.append(b"data: [DONE]\n\n")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=AsyncSSEStream(large_frames),
        )

    transport = httpx.MockTransport(handler)
    upstream_client = httpx.AsyncClient(transport=transport)
    app = create_app(http_client=upstream_client, redactor=StubRedactor(), upstream_base_url="http://headroom.test/v1")
    client = TestClient(app)

    with client.stream("POST", "/v1/responses", json=payload) as response:
        body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert body.count(b"response.output_text.delta") == 40
    assert b"[DONE]" in body
    assert len(body) > 20000
