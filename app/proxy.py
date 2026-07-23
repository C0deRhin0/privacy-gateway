from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from typing import Any

TEXT_PART_TYPES = {"input_text", "text", "output_text"}
STRING_KEYS = {
    "text",
    "content",
    "instructions",
    "system",
    "developer",
    "prompt",
    "query",
    "input_text",
    "user_input",
    "message",
    "context",
    "summary",
}
SKIP_STRING_KEYS = {
    "id",
    "model",
    "type",
    "role",
    "status",
    "name",
    "tool_name",
    "call_id",
    "event_id",
    "item_id",
    "provider",
}


def redact_payload(payload: dict[str, Any], redactor: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _redact_payload(payload, redactor.redact_text)


def redact_payload_secrets(payload: dict[str, Any], redactor: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _redact_payload(payload, redactor.redact_secrets)


def redact_payload_pii(payload: dict[str, Any], redactor: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _redact_payload(payload, redactor.redact_pii)


def _redact_payload(payload: dict[str, Any], redact_text: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rewritten = deepcopy(payload)
    findings: list[dict[str, Any]] = []
    _walk_text(rewritten, lambda text, path: _redact_text(text, redact_text, findings, path), path=())
    return rewritten, findings


def transform_payload_text(payload: dict[str, Any], transform: Any) -> dict[str, Any]:
    rewritten = deepcopy(payload)
    _walk_text(rewritten, transform, path=())
    return rewritten


def rehydrate_response_text(payload: dict[str, Any], token_aliases: dict[str, str], redactor: Any) -> dict[str, Any]:
    """Rehydrate only request-local tokens in OpenAI Responses output text, then DLP it."""
    rewritten = deepcopy(payload)

    def transform(text: str) -> str:
        for token, alias in token_aliases.items():
            text = text.replace(token, alias)
        return _result_text(redactor.redact_text(text))

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                if key == "output_text" and isinstance(item, str):
                    value[key] = transform(item)
                elif key == "text" and value.get("type") in {"output_text", "text"} and isinstance(item, str):
                    value[key] = transform(item)
                elif key == "refusal" and isinstance(item, str):
                    value[key] = transform(item)
                else:
                    value[key] = walk(item)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                value[index] = walk(item)
        return value

    return walk(rewritten)


def _redact_text(text: str, redact_text: Any, findings: list[dict[str, Any]], path: tuple[str, ...]) -> str:
    result = redact_text(text)
    findings.extend(_result_items(result, path))
    return _result_text(result)


def _walk_text(value: Any, transform: Any, path: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        for key, item in list(value.items()):
            next_path = (*path, key)
            if _should_redact_string(key=key, value=item, container=value, path=path):
                value[key] = transform(item, next_path)
                continue
            value[key] = _walk_text(item, transform, next_path)
        return value

    if isinstance(value, list):
        if _list_is_text_parts(value):
            for index, item in enumerate(value):
                text = item.get("text")
                if isinstance(text, str):
                    item["text"] = transform(text, (*path, str(index), "text"))
            return value

        if _should_redact_string_list(path, value):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    value[index] = transform(item, (*path, str(index)))
                else:
                    value[index] = _walk_text(item, transform, (*path, str(index)))
            return value

        for index, item in enumerate(value):
            value[index] = _walk_text(item, transform, (*path, str(index)))
        return value

    return value


def _should_redact_string(*, key: str, value: Any, container: dict[str, Any], path: tuple[str, ...]) -> bool:
    if not isinstance(value, str):
        return False
    if key in SKIP_STRING_KEYS:
        return False
    if key == "text" and container.get("type") in TEXT_PART_TYPES:
        return True
    if key == "input" and not path:
        return True
    return key in STRING_KEYS


def _should_redact_string_list(path: tuple[str, ...], value: Iterable[Any]) -> bool:
    return bool(path) and path[-1] in {"input", "messages", "prompts"} and all(isinstance(item, str) or isinstance(item, (dict, list)) for item in value)


def _list_is_text_parts(value: list[Any]) -> bool:
    return bool(value) and all(isinstance(item, dict) and item.get("type") in TEXT_PART_TYPES and isinstance(item.get("text"), str) for item in value)


def _result_text(result: Any) -> str:
    return result["text"] if isinstance(result, dict) else result.text


def _result_items(result: Any, path: tuple[str, ...]) -> list[dict[str, Any]]:
    raw_items = result.get("items", []) if isinstance(result, dict) else result.items
    normalized: list[dict[str, Any]] = []
    for item in raw_items:
        copied = dict(item)
        copied["path"] = ".".join(path)
        normalized.append(copied)
    return normalized
