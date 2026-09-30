from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SipMessage:
    method: str
    uri: str
    headers: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


def parse_sip_request(data: bytes) -> SipMessage | None:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None

    lines = text.split("\r\n")
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 3 or not parts[2].upper().startswith("SIP/"):
        return None

    method, uri = parts[0], parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    return SipMessage(method=method.upper(), uri=uri, headers=headers, raw=text)


def parse_authorization(header_value: str) -> dict[str, str]:
    """Parse a Digest Authorization/Proxy-Authorization header into its fields."""
    result: dict[str, str] = {}
    if not header_value:
        return result

    _, _, rest = header_value.partition(" ")
    for part in rest.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        result[key.strip().lower()] = value.strip().strip('"')
    return result
