import hashlib

# JA4H: HTTP client fingerprint from FoxIO's JA4+ suite. Built from the
# request line and header *shape* only, so it identifies the client software
# (curl, zgrab, python-requests, a real browser) regardless of the User-Agent
# string it claims.
#
#   JA4H_a_JA4H_b_JA4H_c_JA4H_d
#   a: method(2) version(2) cookie(c|n) referer(r|n) header-count(2) accept-language(4)
#   b: sha256[:12] of header names in wire order, excluding Cookie/Referer
#   c: sha256[:12] of cookie names, sorted
#   d: sha256[:12] of cookie name=value pairs, sorted
#
# Caveat: ASGI hands us header names already lowercased, so for HTTP/1.1
# clients that send mixed-case names JA4H_b can differ from a pcap-based
# tool. It's consistent within this stack, which is what matters for
# clustering clients.

_EMPTY_HASH = "000000000000"

_VERSIONS = {"1.0": "10", "1.1": "11", "2": "20", "2.0": "20", "3": "30", "3.0": "30"}


def _trunc_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12] if s else _EMPTY_HASH


def _lang(accept_language: str | None) -> str:
    if not accept_language:
        return "0000"
    first = accept_language.split(",")[0].split(";")[0].strip().replace("-", "").lower()
    return first[:4].ljust(4, "0") if first else "0000"


def ja4h(method: str, http_version: str, headers: list[tuple[str, str]]) -> tuple[str, str]:
    """Returns (ja4h, ja4h_r). `headers` is (name, value) pairs in wire order;
    ja4h_r is the raw form with the three hashes replaced by their inputs."""
    names: list[str] = []
    cookie: str | None = None
    referer = False
    lang: str | None = None
    for name, value in headers:
        lname = name.lower()
        if lname == "cookie":
            cookie = value
            continue
        if lname == "referer":
            referer = True
            continue
        if lname == "accept-language" and lang is None:
            lang = value
        names.append(name)

    a = (
        f"{method[:2].lower()}"
        f"{_VERSIONS.get(http_version, '00')}"
        f"{'c' if cookie is not None else 'n'}"
        f"{'r' if referer else 'n'}"
        f"{min(len(names), 99):02d}"
        f"{_lang(lang)}"
    )

    cookie_names: list[str] = []
    cookie_pairs: list[str] = []
    if cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if not part:
                continue
            cname, _, cval = part.partition("=")
            cookie_names.append(cname.strip())
            cookie_pairs.append(f"{cname.strip()}={cval.strip()}")

    b_raw = ",".join(names)
    c_raw = ",".join(sorted(cookie_names))
    d_raw = ",".join(sorted(cookie_pairs))
    return (
        f"{a}_{_trunc_hash(b_raw)}_{_trunc_hash(c_raw)}_{_trunc_hash(d_raw)}",
        f"{a}_{b_raw}_{c_raw}_{d_raw}",
    )
