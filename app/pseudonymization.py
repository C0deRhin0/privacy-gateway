from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class PseudonymizationMode(StrEnum):
    BASE = "BASE"
    STANDARD = "STANDARD"
    STRICT = "STRICT"


MODE_ORDER = (PseudonymizationMode.BASE, PseudonymizationMode.STANDARD, PseudonymizationMode.STRICT)
MATCH_TYPES = {"whole_word", "exact"}


class PseudonymizationUnavailable(Exception):
    """Raised when an alias match cannot be safely replaced."""


@dataclass(frozen=True, slots=True)
class ContextEntry:
    entity_type: str
    aliases: tuple[str, ...]
    canonical_id: str
    provider_fallback_token: str | None
    match: str
    nearby_context: tuple[str, ...]
    context_distance: int
    allow_canonical_fallback: bool


@dataclass(frozen=True, slots=True)
class ContextMap:
    routes: dict[str, dict[PseudonymizationMode, tuple[ContextEntry, ...]]]

    def entries_for(self, route: str, mode: PseudonymizationMode | str) -> tuple[ContextEntry, ...]:
        selected = PseudonymizationMode(str(mode).upper())
        route_entries = self.routes.get(route, {})
        entries: list[ContextEntry] = []
        for available_mode in MODE_ORDER[: MODE_ORDER.index(selected) + 1]:
            entries.extend(route_entries.get(available_mode, ()))
        return tuple(entries)

    def has_entries_for(self, route: str) -> bool:
        return any(self.routes.get(route, {}).values())


class ContextMapLoader:
    """Loads a declarative, local JSON map without retaining raw match history."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> ContextMap:
        with self.path.open(encoding="utf-8") as source:
            raw = json.load(source)
        if not isinstance(raw, dict) or not isinstance(raw.get("routes"), dict):
            raise ValueError("context map must contain a routes object")

        routes: dict[str, dict[PseudonymizationMode, tuple[ContextEntry, ...]]] = {}
        for route, mode_map in raw["routes"].items():
            if not isinstance(route, str) or not route.startswith("/") or not isinstance(mode_map, dict):
                raise ValueError("context map routes must be absolute paths with mode objects")
            parsed_modes: dict[PseudonymizationMode, tuple[ContextEntry, ...]] = {}
            for raw_mode, raw_entries in mode_map.items():
                mode = PseudonymizationMode(raw_mode.upper())
                if not isinstance(raw_entries, list):
                    raise ValueError("context map mode values must be lists")
                parsed_modes[mode] = tuple(self._entry(entry) for entry in raw_entries)
            routes[route] = parsed_modes
        return ContextMap(routes)

    @staticmethod
    def _entry(raw: Any) -> ContextEntry:
        if not isinstance(raw, dict):
            raise ValueError("context map entries must be objects")
        entity_type = raw.get("entity_type")
        aliases = raw.get("aliases")
        canonical_id = raw.get("canonical_id")
        provider_fallback_token = raw.get("provider_fallback_token")
        match = raw.get("match", "whole_word")
        nearby_context = raw.get("nearby_context", [])
        context_distance = raw.get("context_distance", 32)
        if (
            not isinstance(entity_type, str)
            or not entity_type
            or not isinstance(aliases, list)
            or not aliases
            or not all(isinstance(alias, str) and alias for alias in aliases)
            or not isinstance(canonical_id, str)
            or not canonical_id
            or canonical_id in aliases
            or provider_fallback_token is not None
            and (not isinstance(provider_fallback_token, str) or not provider_fallback_token)
            or provider_fallback_token in aliases
            or match not in MATCH_TYPES
            or not isinstance(nearby_context, list)
            or not all(isinstance(item, str) and item for item in nearby_context)
            or not isinstance(context_distance, int)
            or context_distance < 0
            or not isinstance(raw.get("allow_canonical_fallback", False), bool)
            or raw.get("allow_canonical_fallback", False)
            and provider_fallback_token is None
        ):
            raise ValueError("invalid context map entry: canonical_id and explicit fallback token are required")
        return ContextEntry(
            entity_type=entity_type,
            aliases=tuple(aliases),
            canonical_id=canonical_id,
            provider_fallback_token=provider_fallback_token,
            match=match,
            nearby_context=tuple(nearby_context),
            context_distance=context_distance,
            allow_canonical_fallback=raw.get("allow_canonical_fallback", False),
        )


@dataclass(frozen=True, slots=True)
class PseudonymizationResult:
    text: str
    active_tokens: set[str]
    token_display_aliases: dict[str, str]


class ContextualPseudonymizer:
    """One-way contextual pseudonymizer. It deliberately provides no rehydration API."""

    def __init__(self, context_map: ContextMap, *, token_key: bytes | None = None):
        self._context_map = context_map
        self._token_key = token_key

    def pseudonymize(
        self,
        text: str,
        *,
        route: str,
        mode: PseudonymizationMode | str,
        scope: str,
    ) -> PseudonymizationResult:
        entries = self._context_map.entries_for(route, mode)
        if not entries:
            return PseudonymizationResult(text=text, active_tokens=set(), token_display_aliases={})

        replacements: list[tuple[int, int, str, str]] = []
        for entry in entries:
            token = self._entry_token(entry, scope)
            for alias in entry.aliases:
                matches = self._matches(text, alias, entry)
                if token is None and matches:
                    raise PseudonymizationUnavailable("no stable token key or permitted fallback")
                display_alias = max(entry.aliases, key=len)
                for match in matches:
                    replacements.append((match.start(), match.end(), token, display_alias))

        replacements.sort(key=lambda item: (-(item[1] - item[0]), item[0]))
        chosen: list[tuple[int, int, str, str]] = []
        for replacement in replacements:
            if not any(replacement[0] < finish and start < replacement[1] for start, finish, _, _ in chosen):
                chosen.append(replacement)
        chosen.sort()
        if not chosen:
            return PseudonymizationResult(text=text, active_tokens=set(), token_display_aliases={})

        parts: list[str] = []
        cursor = 0
        active_tokens: set[str] = set()
        display_aliases_by_token: dict[str, str] = {}
        for start, finish, token, display_alias in chosen:
            parts.extend((text[cursor:start], token))
            cursor = finish
            active_tokens.add(token)
            display_aliases_by_token.setdefault(token, display_alias)
        parts.append(text[cursor:])
        return PseudonymizationResult(
            text="".join(parts),
            active_tokens=active_tokens,
            token_display_aliases=display_aliases_by_token,
        )

    def supports_route(self, route: str) -> bool:
        return self._context_map.has_entries_for(route)

    def is_ready_for_route(self, route: str) -> bool:
        entries = self._context_map.entries_for(route, PseudonymizationMode.STRICT)
        return bool(entries) and (self._token_key is not None or all(entry.allow_canonical_fallback for entry in entries))

    def _matches(self, text: str, alias: str, entry: ContextEntry) -> list[re.Match[str]]:
        if entry.match == "exact":
            candidates = [re.fullmatch(re.escape(alias), text, flags=re.IGNORECASE)]
        else:
            candidates = list(re.finditer(rf"(?<!\w){re.escape(alias)}(?!\w)", text, flags=re.IGNORECASE))
        return [match for match in candidates if match is not None and self._has_context(text, match, entry)]

    @staticmethod
    def _has_context(text: str, match: re.Match[str], entry: ContextEntry) -> bool:
        if not entry.nearby_context:
            return True
        start = max(0, match.start() - entry.context_distance)
        finish = min(len(text), match.end() + entry.context_distance)
        nearby = text[start:finish]
        return any(re.search(rf"(?<!\w){re.escape(item)}(?!\w)", nearby, flags=re.IGNORECASE) for item in entry.nearby_context)

    def _entry_token(self, entry: ContextEntry, scope: str) -> str | None:
        if self._token_key is None:
            if entry.allow_canonical_fallback:
                return entry.provider_fallback_token
            return None
        return self._token(entry.entity_type, entry.canonical_id, scope)

    def _token(self, entity_type: str, canonical_id: str, scope: str) -> str:
        digest = hmac.new(self._token_key, f"{scope}\0{entity_type}\0{canonical_id}".encode(), hashlib.sha256).digest()
        identifier = base64.urlsafe_b64encode(digest[:18]).decode().rstrip("=")
        return f"<PG:{entity_type}:{identifier}>"
