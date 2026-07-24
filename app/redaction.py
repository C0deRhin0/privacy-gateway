from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_DIGIT_RE = re.compile(r"\d")
DATEISH_PHONE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?: \d{1,2})?$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
GENERIC_SECRET_RE = re.compile(r"^(?:sk|rk|pk|xoxb|ghp|github_pat|hf|AIza)[-_A-Za-z0-9]{16,}$")
PARTIAL_SECRET_RE = re.compile(r"^(?:sk|rk|pk|xoxb|ghp|github_pat|hf|AIza)[-_A-Za-z0-9]{4,}\.\.\.[-_A-Za-z0-9]{4,}$")
SECRET_ENTITY_TYPES = frozenset({"API_SECRET", "JWT_TOKEN"})
GENERIC_PII_ENTITY_TYPES = frozenset({"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IP_ADDRESS"})


@dataclass(slots=True)
class RedactionResult:
    text: str
    items: list[dict[str, Any]]


class PresidioRedactor:
    def __init__(self) -> None:
        registry = RecognizerRegistry()
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="EMAIL_ADDRESS",
                patterns=[Pattern(name="email", regex=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", score=0.95)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="PHONE_NUMBER",
                patterns=[Pattern(name="phone", regex=r"(?:\+?\d[\d\-() ]{8,}\d)", score=0.7)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="CREDIT_CARD",
                patterns=[Pattern(name="credit-card", regex=r"\b(?:\d[ -]*?){13,19}\b", score=0.7)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="US_SSN",
                patterns=[Pattern(name="ssn", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.95)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="IP_ADDRESS",
                patterns=[Pattern(name="ip-address", regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b", score=0.6)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="JWT_TOKEN",
                patterns=[Pattern(name="jwt", regex=r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", score=0.85)],
            )
        )
        registry.add_recognizer(
            PatternRecognizer(
                supported_entity="API_SECRET",
                patterns=[
                    Pattern(name="generic-secret", regex=r"(?:sk|rk|pk|xoxb|ghp|github_pat|hf|AIza)[-_A-Za-z0-9]{16,}", score=0.8),
                    Pattern(name="partial-secret", regex=r"(?:sk|rk|pk|xoxb|ghp|github_pat|hf|AIza)[-_A-Za-z0-9]{4,}\.\.\.[-_A-Za-z0-9]{4,}", score=0.75),
                ],
            )
        )
        self._registry = registry
        self._anonymizer = AnonymizerEngine()

    def redact_text(self, text: str) -> RedactionResult:
        return self._redact(text)

    def redact_secrets(self, text: str) -> RedactionResult:
        return self._redact(text, SECRET_ENTITY_TYPES)

    def redact_pii(self, text: str) -> RedactionResult:
        return self._redact(text, GENERIC_PII_ENTITY_TYPES)

    def _redact(self, text: str, entity_types: frozenset[str] | None = None) -> RedactionResult:
        results = self._deduplicate(self._analyze(text, entity_types))
        operators = {
            item.entity_type: OperatorConfig("replace", {"new_value": f"<{item.entity_type}>"})
            for item in results
        }
        anonymized = self._anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
        items = [
            {
                "entity_type": item.entity_type,
                "start": item.start,
                "end": item.end,
                "score": item.score,
                "text": text[item.start:item.end],
            }
            for item in results
        ]
        return RedactionResult(text=anonymized.text, items=items)

    def _analyze(self, text: str, entity_types: frozenset[str] | None = None) -> list[RecognizerResult]:
        results: list[RecognizerResult] = []
        for recognizer in self._registry.recognizers:
            entity_type = recognizer.supported_entities[0]
            if entity_types is not None and entity_type not in entity_types:
                continue
            results.extend(recognizer.analyze(text=text, entities=[entity_type], nlp_artifacts=None))
        return [item for item in results if self._is_valid_match(item, text)]

    def _is_valid_match(self, item: RecognizerResult, text: str) -> bool:
        snippet = text[item.start:item.end]
        entity = item.entity_type
        if entity == "EMAIL_ADDRESS":
            return bool(EMAIL_RE.fullmatch(snippet))
        if entity == "PHONE_NUMBER":
            digits = PHONE_DIGIT_RE.findall(snippet)
            if not (10 <= len(digits) <= 15) or snippet.isdigit():
                return False
            if DATEISH_PHONE_RE.fullmatch(snippet) or ':' in snippet:
                return False
            return True
        if entity == "CREDIT_CARD":
            digits = ''.join(PHONE_DIGIT_RE.findall(snippet))
            return 13 <= len(digits) <= 19 and self._passes_luhn(digits)
        if entity == "IP_ADDRESS":
            parts = snippet.split('.')
            return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        if entity == "JWT_TOKEN":
            if not JWT_RE.fullmatch(snippet):
                return False
            parts = snippet.split('.')
            return len(parts) == 3 and all(len(part) >= 8 for part in parts)
        if entity == "API_SECRET":
            return bool(GENERIC_SECRET_RE.fullmatch(snippet) or PARTIAL_SECRET_RE.fullmatch(snippet))
        return True

    def _deduplicate(self, results: list[RecognizerResult]) -> list[RecognizerResult]:
        ordered = sorted(results, key=lambda item: (item.start, -(item.end - item.start), -item.score))
        deduped: list[RecognizerResult] = []
        for item in ordered:
            if deduped and item.start >= deduped[-1].start and item.end <= deduped[-1].end:
                continue
            deduped.append(item)
        return deduped

    def _passes_luhn(self, digits: str) -> bool:
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            digit = int(char)
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0
