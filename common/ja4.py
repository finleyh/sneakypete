import hashlib

# JA4: TLS client fingerprint from FoxIO's JA4+ suite, computed from the raw
# ClientHello bytes. Unlike JA4H (which ASGI distorts) this is built straight
# from the wire, so it should match external JA4 databases exactly.
#
#   JA4_a_JA4_b_JA4_c
#   a: "t" + tls version(2) + sni(d|i) + cipher count(2) + extension count(2) + alpn(2)
#   b: sha256[:12] of cipher suites minus GREASE, 4-hex lowercase, sorted, comma-joined
#   c: sha256[:12] of extensions minus GREASE/SNI/ALPN, sorted, then "_" + signature
#      algorithms in original order (no "_" part when there are none)

_EMPTY_HASH = "000000000000"
_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
_SNI, _ALPN, _SIGALGS, _SUPPORTED_VERSIONS = 0x0000, 0x0010, 0x000D, 0x002B


class ClientHelloError(ValueError):
    pass


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _u16(b: bytes, i: int) -> int:
    return int.from_bytes(b[i:i + 2], "big")


def parse_client_hello(data: bytes) -> dict:
    """Parse the TLS record(s) holding a ClientHello. Raises ClientHelloError
    for non-TLS input; the message for a truncated hello starts with
    'truncated' so a caller can keep reading and retry."""
    if len(data) < 5:
        raise ClientHelloError("truncated: record header")
    if data[0] != 0x16 or data[1] != 0x03:
        raise ClientHelloError("not a TLS handshake record")

    handshake = bytearray()
    i = 0
    while i + 5 <= len(data):
        if data[i] != 0x16:
            raise ClientHelloError("not a TLS handshake record")
        rlen = _u16(data, i + 3)
        handshake += data[i + 5:i + 5 + rlen]
        i += 5 + rlen
        if len(handshake) >= 4 and len(handshake) >= 4 + int.from_bytes(handshake[1:4], "big"):
            break
    if len(handshake) < 4:
        raise ClientHelloError("truncated: handshake header")
    if handshake[0] != 0x01:
        raise ClientHelloError("not a ClientHello")
    hlen = int.from_bytes(handshake[1:4], "big")
    if len(handshake) < 4 + hlen:
        raise ClientHelloError("truncated: ClientHello body")
    body = bytes(handshake[4:4 + hlen])

    try:
        p = 0
        legacy_version = _u16(body, p)
        p += 2 + 32  # version + random
        p += 1 + body[p]  # session id
        cs_len = _u16(body, p)
        p += 2
        ciphers = [_u16(body, p + j) for j in range(0, cs_len, 2)]
        p += cs_len
        p += 1 + body[p]  # compression methods

        extensions: list[int] = []
        sni = False
        alpn: list[bytes] = []
        sigalgs: list[int] = []
        supported_versions: list[int] = []
        if p + 2 <= len(body):
            end = min(p + 2 + _u16(body, p), len(body))
            p += 2
            while p + 4 <= end:
                etype, elen = _u16(body, p), _u16(body, p + 2)
                p += 4
                edata = body[p:p + elen]
                p += elen
                extensions.append(etype)
                if etype == _SNI:
                    sni = True
                elif etype == _ALPN and len(edata) >= 2:
                    q = 2
                    while q < len(edata):
                        n = edata[q]
                        alpn.append(edata[q + 1:q + 1 + n])
                        q += 1 + n
                elif etype == _SIGALGS and len(edata) >= 2:
                    n = min(_u16(edata, 0), len(edata) - 2)
                    sigalgs = [_u16(edata, 2 + j) for j in range(0, n, 2)]
                elif etype == _SUPPORTED_VERSIONS and len(edata) >= 1:
                    n = min(edata[0], len(edata) - 1)
                    supported_versions = [_u16(edata, 1 + j) for j in range(0, n, 2)]
    except IndexError as e:
        raise ClientHelloError("malformed ClientHello") from e

    return {
        "legacy_version": legacy_version,
        "ciphers": ciphers,
        "extensions": extensions,
        "sni": sni,
        "alpn": alpn,
        "sigalgs": sigalgs,
        "supported_versions": supported_versions,
    }


def _alpn_code(value: bytes) -> str:
    if not value:
        return "00"
    first, last = value[0], value[-1]

    def alnum(b: int) -> bool:
        return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A

    if alnum(first) and alnum(last):
        return chr(first) + chr(last)
    return f"{first:02x}"[0] + f"{last:02x}"[1]


def _trunc_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else _EMPTY_HASH


def ja4(hello: dict) -> tuple[str, str]:
    """Returns (ja4, ja4_r) for a parsed ClientHello; ja4_r is the raw form
    with the two hashes replaced by their inputs."""
    versions = [v for v in hello["supported_versions"] if not is_grease(v)]
    version = max(versions) if versions else hello["legacy_version"]
    ciphers = [c for c in hello["ciphers"] if not is_grease(c)]
    extensions = [e for e in hello["extensions"] if not is_grease(e)]
    alpn = _alpn_code(hello["alpn"][0] if hello["alpn"] else b"")

    a = (
        f"t{_VERSIONS.get(version, '00')}{'d' if hello['sni'] else 'i'}"
        f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn}"
    )
    b_raw = ",".join(f"{c:04x}" for c in sorted(ciphers))
    hashed_exts = sorted(e for e in extensions if e not in (_SNI, _ALPN))
    c_raw = ",".join(f"{e:04x}" for e in hashed_exts)
    if c_raw and hello["sigalgs"]:
        c_raw += "_" + ",".join(f"{s:04x}" for s in hello["sigalgs"])
    return f"{a}_{_trunc_hash(b_raw)}_{_trunc_hash(c_raw)}", f"{a}_{b_raw}_{c_raw}"


def tls_version_name(hello: dict) -> str:
    versions = [v for v in hello["supported_versions"] if not is_grease(v)]
    return _VERSIONS.get(max(versions) if versions else hello["legacy_version"], "00")
