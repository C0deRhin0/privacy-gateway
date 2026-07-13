from __future__ import annotations

import json
import os

import httpx


def main() -> None:
    base_url = os.getenv("PRIVACY_GATEWAY_BASE_URL", "http://127.0.0.1:14000/v1")
    payload = {
        "model": "gpt-5.4",
        "stream": False,
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "My email is alice@example.com and my phone is +1 415 555 0124"}
                ],
            }
        ],
    }

    response = httpx.post(f"{base_url.rstrip('/')}/responses", json=payload, timeout=60)
    print(f"status={response.status_code}")
    print(f"x-privacy-gateway-findings={response.headers.get('x-privacy-gateway-findings')}")
    print(json.dumps(response.json(), indent=2)[:2000])


if __name__ == "__main__":
    main()
