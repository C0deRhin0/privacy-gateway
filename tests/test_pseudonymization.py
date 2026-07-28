import json
import logging
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from app.pseudonymization import ContextMapLoader, ContextualPseudonymizer, PseudonymizationMode, PseudonymizationUnavailable


FIXTURE_MAP = Path(__file__).parent / "fixtures" / "fictional_context_map.json"


class StubRedactor:
    def redact_secrets(self, text: str):
        return {"text": text, "items": []}

    def redact_pii(self, text: str):
        return self.redact_text(text)

    def redact_text(self, text: str):
        return {"text": text.replace("alice@example.com", "<EMAIL_ADDRESS>"), "items": []}


class AsyncSSEStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


def pseudonymizer() -> ContextualPseudonymizer:
    return ContextualPseudonymizer(
        ContextMapLoader(FIXTURE_MAP).load(),
        token_key=b"test-only-hmac-key",
    )


def test_loader_selects_route_and_cumulative_mode_entries():
    loaded = ContextMapLoader(FIXTURE_MAP).load()

    assert [entry.canonical_id for entry in loaded.entries_for("/mac/v1/responses", PseudonymizationMode.BASE)] == [
        "org-northstar-labs",
        "person-dr-quill",
    ]
    assert len(loaded.entries_for("/mac/v1/responses", PseudonymizationMode.STANDARD)) == 3
    assert len(loaded.entries_for("/mac/v1/responses", PseudonymizationMode.STRICT)) == 4
    assert loaded.entries_for("/v1/responses", PseudonymizationMode.STRICT) == ()


def test_longest_whole_word_alias_wins_and_substrings_do_not_match():
    result = pseudonymizer().pseudonymize(
        "Northstar Labs spoke to Northstar; Northstarship stays.",
        route="/mac/v1/responses",
        mode=PseudonymizationMode.BASE,
        scope="conversation-1",
    )

    assert result.text.count("<PG:ORGANIZATION:") == 2
    assert "Northstar Labs" not in result.text
    assert "Northstarship" in result.text
    assert len(result.active_tokens) == 1


def test_exact_and_nearby_context_matches_are_opt_in():
    engine = pseudonymizer()

    assert "<PG:PERSON:" in engine.pseudonymize(
        "Dr. Quill", route="/mac/v1/responses", mode="BASE", scope="one"
    ).text
    assert "Dr. Quill spoke" in engine.pseudonymize(
        "Dr. Quill spoke", route="/mac/v1/responses", mode="BASE", scope="one"
    ).text
    assert "<PG:PROJECT:" in engine.pseudonymize(
        "The Atlas project is fictional.", route="/mac/v1/responses", mode="STANDARD", scope="one"
    ).text
    assert "Atlas is fictional." == engine.pseudonymize(
        "Atlas is fictional.", route="/mac/v1/responses", mode="STANDARD", scope="one"
    ).text


def test_hmac_tokens_are_scope_bound_and_request_local():
    engine = pseudonymizer()
    first = engine.pseudonymize("Northstar", route="/mac/v1/responses", mode="BASE", scope="request-a")
    repeat = engine.pseudonymize("Northstar", route="/mac/v1/responses", mode="BASE", scope="request-a")
    second = engine.pseudonymize("Northstar", route="/mac/v1/responses", mode="BASE", scope="request-b")

    assert first.text == repeat.text
    assert first.text != second.text
    assert first.active_tokens == {first.text}
    assert "Northstar" not in first.text


def test_missing_key_fails_closed_when_any_matched_entry_lacks_permitted_fallback(tmp_path):
    map_path = tmp_path / "map.json"
    map_path.write_text(
        json.dumps(
            {
                "routes": {
                    "/test": {
                        "BASE": [
                            {"entity_type": "PERSON", "canonical_id": "blocked", "aliases": ["Alias"], "match": "whole_word"},
                            {
                                "entity_type": "PERSON",
                                "canonical_id": "allowed",
                                "aliases": ["Allowed Alias"],
                                "match": "whole_word",
                                "allow_canonical_fallback": True,
                                "provider_fallback_token": "provider-allowed",
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    engine = ContextualPseudonymizer(ContextMapLoader(map_path).load())

    with pytest.raises(PseudonymizationUnavailable):
        engine.pseudonymize("Alias and Allowed Alias", route="/test", mode="BASE", scope="one")


def test_explicit_route_redacts_before_pseudonymizing_and_preserves_existing_route():
    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={"status": "completed"})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )
    client = TestClient(app)
    payload = {"input": [{"role": "user", "content": [{"type": "input_text", "text": "Northstar Labs alice@example.com"}]}]}

    pseudonymized = client.post(
        "/mac/v1/responses",
        headers={"x-privacy-gateway-conversation-id": "fictional-conversation"},
        json=payload,
    )
    original = client.post("/v1/responses", json=payload)

    assert pseudonymized.status_code == 200
    assert "<EMAIL_ADDRESS>" in captured[0]["input"][0]["content"][0]["text"]
    assert "<PG:ORGANIZATION:" in captured[0]["input"][0]["content"][0]["text"]
    assert original.status_code == 200
    assert captured[1]["input"][0]["content"][0]["text"] == "Northstar Labs <EMAIL_ADDRESS>"


def test_explicit_route_traverses_existing_text_payload_shapes():
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content.decode()))
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )
    response = TestClient(app).post(
        "/mac/v1/responses",
        headers={"x-privacy-gateway-pseudonymization-mode": "STRICT", "x-request-id": "fixture-request"},
        json={"instructions": "Northstar", "messages": [{"content": "Harbor Seven"}], "prompt": "Harbor"},
    )

    assert response.status_code == 200
    assert all("<PG:" in value for value in (captured["instructions"], captured["messages"][0]["content"], captured["prompt"]))


def test_mac_route_pseudonymizes_network_aliases_after_secrets_and_before_generic_pii(tmp_path):
    context_map = tmp_path / "fictional-network-map.json"
    fake_secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
    context_map.write_text(
        json.dumps(
            {
                "routes": {
                    "/mac/v1/responses": {
                        "BASE": [
                            {
                                "entity_type": "NETWORK",
                                "canonical_id": "fictional-edge-a",
                                "aliases": ["198.51.100.42", "203.0.113.77"],
                            },
                            {
                                "entity_type": "CREDENTIAL",
                                "canonical_id": "fictional-test-secret",
                                "aliases": [fake_secret],
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    captured = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content.decode()))
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=context_map,
        pseudonymization_token_key=b"test-only-hmac-key",
    )
    response = TestClient(app).post(
        "/mac/v1/responses",
        headers={"x-privacy-gateway-pseudonymization-mode": "BASE", "x-privacy-gateway-conversation-id": "fictional-network"},
        json={
            "instructions": "Route to 198.51.100.42 using " + fake_secret,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "Backup is 203.0.113.77"}]}],
            "messages": [{"content": "Primary remains 198.51.100.42"}],
            "prompt": "Verify 203.0.113.77",
        },
    )

    assert response.status_code == 200
    assert "<API_SECRET>" in captured["instructions"]
    assert fake_secret not in captured["instructions"]
    assert "<PG:CREDENTIAL:" not in captured["instructions"]
    assert all(
        "<PG:NETWORK:" in value
        for value in (
            captured["instructions"],
            captured["input"][0]["content"][0]["text"],
            captured["messages"][0]["content"],
            captured["prompt"],
        )
    )
    assert "<IP_ADDRESS>" not in json.dumps(captured)


def test_mac_route_profile_scoped_rehydrates_only_exact_tokens_active_in_the_current_request():
    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded = json.loads(request.content.decode())
        captured.append(forwarded)
        token = forwarded["input"]
        return httpx.Response(200, json={"output_text": f"The organization is {token}. Unknown <PG:ORG:invented> stays."})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post(
        "/mac/v1/responses",
        headers={"x-privacy-gateway-conversation-id": "authorized-mac-conversation"},
        json={"input": "Northstar Labs"},
    )

    assert response.status_code == 200
    assert "Northstar Labs" not in captured[0]["input"]
    assert "<PG:ORGANIZATION:" in captured[0]["input"]
    assert response.json()["output_text"] == "The organization is Northstar Labs. Unknown <PG:ORG:invented> stays."


def test_ordinary_route_never_rehydrates_provider_output():
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"output_text": "<PG:ORGANIZATION:provider-token>"})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post("/v1/responses", json={"input": "Northstar Labs"})

    assert response.status_code == 200
    assert response.json()["output_text"] == "<PG:ORGANIZATION:provider-token>"


def test_mac_rehydration_applies_dlp_to_user_visible_refusal_text():
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"refusal": "Contact alice@example.com"})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Northstar Labs"})

    assert response.status_code == 200
    assert response.json()["refusal"] == "Contact <EMAIL_ADDRESS>"


def test_mac_rehydration_uses_the_map_canonical_display_alias_when_current_request_has_multiple_aliases():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"].split()[0]
        return httpx.Response(200, json={"output_text": token})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Northstar and Northstar Labs"})

    assert response.status_code == 200
    assert response.json()["output_text"] == "Northstar Labs"


def test_mac_route_does_not_rehydrate_a_token_from_another_request():
    forwarded_tokens: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded_tokens.append(json.loads(request.content.decode())["input"])
        return httpx.Response(200, json={"output_text": forwarded_tokens[0]})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )
    client = TestClient(app)

    assert client.post("/mac/v1/responses", json={"input": "Northstar Labs"}).status_code == 200
    response = client.post("/mac/v1/responses", json={"input": "No mapped aliases"})

    assert response.status_code == 200
    assert response.json()["output_text"] == forwarded_tokens[0]


def test_mac_stream_rehydrates_active_delta_and_completed_text_then_applies_dlp():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        frames = [
            f'data: {{"type":"response.output_text.delta","delta":"Alias {token}; alice@example.com"}}\n\n'.encode(),
            f'data: {{"type":"response.completed","response":{{"output_text":"Completed {token}"}}}}\n\n'.encode(),
            b"data: [DONE]\n\n",
        ]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=AsyncSSEStream(frames))

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    with TestClient(app).stream("POST", "/mac/v1/responses", json={"input": "Northstar Labs", "stream": True}) as response:
        body = b"".join(response.iter_bytes()).decode()

    assert response.status_code == 200
    assert "Alias Northstar Labs; <EMAIL_ADDRESS>" in body
    assert "Completed Northstar Labs" in body
    assert "alice@example.com" not in body


def test_mac_rehydrates_sse_response_when_upstream_streams_without_a_stream_request_flag():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        body = f'data: {{"type":"response.output_text.delta","delta":"Alias {token}"}}\n\ndata: [DONE]\n\n'.encode()
        return httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=body)

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Northstar Labs"})

    assert response.status_code == 200
    assert "Alias Northstar Labs" in response.text
    assert "<PG:" not in response.text


def test_mac_rehydrates_active_tokens_in_unknown_text_protocol_and_applies_dlp():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        return httpx.Response(200, headers={"content-type": "application/x-provider-event"}, content=f"Alias {token}; alice@example.com".encode())

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Northstar Labs"})

    assert response.status_code == 200
    assert response.text == "Alias Northstar Labs; <EMAIL_ADDRESS>"


def test_mac_stream_rehydrates_and_applies_dlp_to_refusal_delta():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        frames = [
            f'data: {{"type":"response.refusal.delta","delta":"Refusal {token}; alice@example.com"}}\n\n'.encode(),
            b"data: [DONE]\n\n",
        ]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=AsyncSSEStream(frames))

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    with TestClient(app).stream("POST", "/mac/v1/responses", json={"input": "Northstar Labs", "stream": True}) as response:
        body = b"".join(response.iter_bytes()).decode()

    assert response.status_code == 200
    assert "Refusal Northstar Labs; <EMAIL_ADDRESS>" in body
    assert "alice@example.com" not in body


def test_mac_stream_rehydrates_active_token_split_across_deltas_without_emitting_fragments():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        split_at = len(token) // 2
        frames = [
            f'data: {{"type":"response.output_text.delta","delta":"Alias {token[:split_at]}"}}\n\n'.encode(),
            f'data: {{"type":"response.output_text.delta","delta":"{token[split_at:]} complete"}}\n\n'.encode(),
            b"data: [DONE]\n\n",
        ]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=AsyncSSEStream(frames))

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    with TestClient(app).stream("POST", "/mac/v1/responses", json={"input": "Northstar Labs", "stream": True}) as response:
        body = b"".join(response.iter_bytes()).decode()

    assert response.status_code == 200
    deltas = [json.loads(line[6:])["delta"] for line in body.splitlines() if "response.output_text.delta" in line]
    assert "".join(deltas) == "Alias Northstar Labs complete"
    assert "<PG:" not in body


def test_mac_stream_rehydrates_output_text_done_and_leaves_invented_tokens_literal():
    async def handler(request: httpx.Request) -> httpx.Response:
        token = json.loads(request.content.decode())["input"]
        frame = (
            f'data: {{"type":"response.output_text.done","text":"Done {token}; <PG:ORGANIZATION:invented>"}}\n\n'.encode()
        )
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=AsyncSSEStream([frame, b"data: [DONE]\n\n"]))

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    with TestClient(app).stream("POST", "/mac/v1/responses", json={"input": "Northstar Labs", "stream": True}) as response:
        body = b"".join(response.iter_bytes()).decode()

    assert response.status_code == 200
    assert "Done Northstar Labs; <PG:ORGANIZATION:invented>" in body


def test_context_map_requires_canonical_id_and_explicit_provider_fallback_token(tmp_path):
    invalid_map = tmp_path / "invalid.json"
    invalid_map.write_text(
        json.dumps(
            {
                "routes": {
                    "/mac/v1/responses": {
                        "BASE": [{"entity_type": "PERSON", "aliases": ["Raw Alias"]}]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="canonical_id"):
        ContextMapLoader(invalid_map).load()


def test_unkeyed_fallback_uses_configured_provider_token_not_raw_alias(tmp_path):
    map_path = tmp_path / "fallback.json"
    map_path.write_text(
        json.dumps(
            {
                "routes": {
                    "/mac/v1/responses": {
                        "BASE": [
                            {
                                "entity_type": "PERSON",
                                "canonical_id": "person-001",
                                "aliases": ["Raw Alias"],
                                "allow_canonical_fallback": True,
                                "provider_fallback_token": "provider-person-001",
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = ContextualPseudonymizer(ContextMapLoader(map_path).load()).pseudonymize(
        "Raw Alias", route="/mac/v1/responses", mode="BASE", scope="scope"
    )

    assert result.text == "provider-person-001"
    assert "Raw Alias" not in result.text


def test_longest_alias_wins_globally_across_entries(tmp_path):
    map_path = tmp_path / "overlapping.json"
    map_path.write_text(
        json.dumps(
            {
                "routes": {
                    "/mac/v1/responses": {
                        "BASE": [
                            {"entity_type": "PROJECT", "canonical_id": "short", "aliases": ["Northstar"]},
                            {"entity_type": "ORG", "canonical_id": "long", "aliases": ["Northstar Labs"]},
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    engine = ContextualPseudonymizer(ContextMapLoader(map_path).load(), token_key=b"stable-key")

    result = engine.pseudonymize("Northstar Labs", route="/mac/v1/responses", mode="BASE", scope="scope")

    assert result.text.startswith("<PG:ORG:")


def test_mac_route_fails_closed_without_an_explicit_context_map():
    forwarded = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
    )
    client = TestClient(app)

    mac_response = client.post("/mac/v1/responses", json={"input": "Northstar"})
    ordinary_response = client.post("/v1/responses", json={"input": "Northstar"})

    assert mac_response.status_code == 503
    assert ordinary_response.status_code == 200
    assert len(forwarded) == 1


def test_mac_context_readiness_requires_a_loaded_map_with_usable_entries():
    unavailable_app = create_app(http_client=httpx.AsyncClient(), redactor=StubRedactor())
    keyed_app = create_app(
        http_client=httpx.AsyncClient(),
        redactor=StubRedactor(),
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"test-only-hmac-key",
    )

    unavailable_client = TestClient(unavailable_app)
    keyed_client = TestClient(keyed_app)

    assert unavailable_client.get("/readyz").status_code == 200
    assert unavailable_client.get("/mac/readyz").status_code == 503
    assert unavailable_client.get("/mac/readyz").json() == {"status": "unavailable"}
    assert keyed_client.get("/mac/readyz").status_code == 200
    assert keyed_client.get("/mac/readyz").json() == {"status": "ready"}


def test_mac_context_readiness_accepts_a_map_with_only_permitted_fallbacks(tmp_path):
    map_path = tmp_path / "fallback-only-map.json"
    map_path.write_text(
        json.dumps(
            {
                "routes": {
                    "/mac/v1/responses": {
                        "BASE": [
                            {
                                "entity_type": "PERSON",
                                "canonical_id": "person-001",
                                "aliases": ["Raw Alias"],
                                "allow_canonical_fallback": True,
                                "provider_fallback_token": "provider-person-001",
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = create_app(http_client=httpx.AsyncClient(), redactor=StubRedactor(), context_map_path=map_path)

    response = TestClient(app).get("/mac/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_mac_context_readiness_reports_generic_status_and_log_for_map_load_failure(tmp_path, caplog):
    missing_map = tmp_path / "private-map.json"

    with caplog.at_level(logging.ERROR, logger="app.main"):
        app = create_app(http_client=httpx.AsyncClient(), redactor=StubRedactor(), context_map_path=missing_map)

    response = TestClient(app).get("/mac/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert [record.getMessage() for record in caplog.records] == ["context_map_load_failed"]
    assert all(not record.args for record in caplog.records)


def test_mac_route_fails_closed_when_the_configured_map_has_no_mac_entries(tmp_path):
    map_path = tmp_path / "wrong-route.json"
    map_path.write_text(
        json.dumps(
            {
                "routes": {
                    "/another-route": {
                        "BASE": [{"entity_type": "PERSON", "canonical_id": "person-1", "aliases": ["Alias"]}]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={}))),
        redactor=StubRedactor(),
        context_map_path=map_path,
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Alias"})
    readiness = TestClient(app).get("/mac/readyz")

    assert response.status_code == 503
    assert readiness.status_code == 503
    assert readiness.json() == {"status": "unavailable"}


def test_mac_route_fails_closed_for_matching_entries_without_a_key_or_permitted_fallback():
    forwarded = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        context_map_path=FIXTURE_MAP,
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "Northstar"})
    readiness = TestClient(app).get("/mac/readyz")

    assert response.status_code == 503
    assert readiness.status_code == 503
    assert readiness.json() == {"status": "unavailable"}
    assert forwarded == []


def test_mac_route_fails_closed_when_unready_map_payload_has_no_mapped_alias():
    forwarded = []

    async def handler(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        context_map_path=FIXTURE_MAP,
    )

    response = TestClient(app).post("/mac/v1/responses", json={"input": "No mapped aliases here"})

    assert response.status_code == 503
    assert forwarded == []


def test_mac_route_rejects_invalid_mode_and_keeps_reserved_headers_upstream_free():
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"stable-key",
    )
    client = TestClient(app)

    invalid = client.post(
        "/mac/v1/responses",
        headers={"x-privacy-gateway-pseudonymization-mode": "unsafe"},
        json={"input": "Northstar"},
    )
    valid = client.post(
        "/mac/v1/responses",
        headers={
            "x-privacy-gateway-pseudonymization-mode": "BASE",
            "x-privacy-gateway-conversation-id": "same-scope",
            "x-privacy-gateway-scope": "ignored-scope",
            "X-Privacy-Gateway-Unexpected-Control": "client-supplied",
        },
        json={"input": "Northstar"},
    )

    assert invalid.status_code == 400
    assert valid.status_code == 200
    assert "x-privacy-gateway-pseudonymization-mode" not in captured[0].headers
    assert "x-privacy-gateway-conversation-id" not in captured[0].headers
    assert "x-privacy-gateway-scope" not in captured[0].headers
    assert "x-privacy-gateway-unexpected-control" not in captured[0].headers
    assert "<PG:" not in " ".join(f"{key}: {value}" for key, value in valid.headers.items())


def test_mac_route_tokens_are_scoped_and_missing_scope_is_request_local():
    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content.decode()))
        return httpx.Response(200, json={})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"stable-key",
    )
    client = TestClient(app)
    payload = {"input": "Northstar"}

    for scope in ("scope-a", "scope-a", "scope-b", None, None):
        headers = {"x-privacy-gateway-conversation-id": scope} if scope else {}
        assert client.post("/mac/v1/responses", headers=headers, json=payload).status_code == 200

    tokens = [item["input"] for item in captured]
    assert tokens[0] == tokens[1]
    assert tokens[0] != tokens[2]
    assert tokens[3] != tokens[4]


def test_mac_anthropic_messages_route_pseudonymizes_outbound_text_and_rehydrates_content_response():
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        body = json.loads(request.content.decode())
        protected_token = body["messages"][0]["content"]
        return httpx.Response(200, json={"content": [{"type": "text", "text": f"Approved: {protected_token}"}]})

    app = create_app(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        redactor=StubRedactor(),
        upstream_base_url="http://fictional.test/v1",
        context_map_path=FIXTURE_MAP,
        pseudonymization_token_key=b"stable-key",
    )

    response = TestClient(app).post(
        "/mac/anthropic/v1/messages",
        headers={"x-privacy-gateway-conversation-id": "anthropic-session"},
        json={"model": "claude-test", "messages": [{"role": "user", "content": "Northstar"}]},
    )

    assert response.status_code == 200
    assert captured[0].url.path == "/v1/messages"
    forwarded = json.loads(captured[0].content.decode())
    assert "Northstar" not in forwarded["messages"][0]["content"]
    assert "<PG:" in forwarded["messages"][0]["content"]
    assert response.json()["content"][0]["text"] == "Approved: Northstar Labs"
