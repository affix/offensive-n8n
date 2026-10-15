"""Security-signal scoring shared by source hunks and decompiled binary function diffs."""

from __future__ import annotations

import re
from dataclasses import dataclass

IC = re.IGNORECASE


@dataclass(frozen=True)
class Signal:
    name: str
    weight: float
    pattern: re.Pattern[str]
    side: str = "added"  # added | removed | both


SIGNALS: list[Signal] = [
    Signal("bounds_check", 3.0, re.compile(r"\b(if|while|assert|require|check)\b.*(<=?|>=?).*\b(len|length|size|sizeof|count|capacity|bound|limit|max\w*|offset|idx|index|n_?bytes|remaining)\b|\b(len|length|size|sizeof|count|offset|remaining)\w*\s*(<=?|>=?)", IC)),
    Signal("overflow_guard", 3.0, re.compile(r"__builtin_\w+_overflow|checked_(add|mul|sub)|saturating_|overflow|SIZE_MAX|INT_MAX|UINT\d*_MAX|SSIZE_MAX|Math\.(addExact|multiplyExact)|safe_(add|mul)", IC)),
    Signal("int_width", 2.5, re.compile(r"\b(u?int(8|16|32|64)_t|size_t|ssize_t|off_t|uint|ulong|u(8|16|32|64)|i(8|16|32|64)|long long|unsigned)\b"), "both"),
    Signal("copy_alloc_site", 1.5, re.compile(r"\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|gets|read|recv|fread|malloc|calloc|realloc|alloca|new\s*\w*\s*\[|arraycopy|Buffer\.(alloc|from)|copy_from_user|copy_to_user)\s*\(", IC), "both"),
    Signal("null_check", 1.0, re.compile(r"(==|!=)\s*(NULL|nullptr|nil|null|None)\b|\bis (not )?None\b|=== ?(null|undefined)|\?\.", IC)),
    Signal("auth_check", 3.0, re.compile(r"\b(auth\w*|authori[sz]\w*|permission\w*|is_?admin|has_?role|check_?access|access_?check|acl\w*|privilege\w*|csrf\w*|require_?login|login_?required|is_?authenticated|verify_?(token|signature|session)|session\w*|scope|capabilit\w*)\b", IC)),
    Signal("path_guard", 3.0, re.compile(r"\b(realpath|normpath|normali[sz]e|canonical\w*|abspath|resolve|is_relative_to|commonpath|basename|startswith|starts_with|startsWith|path\.Clean|filepath\.(Clean|Rel)|getCanonicalPath)\b|\.\./|\\.\\.\\\\|%2e%2e", IC)),
    Signal("sanitise", 2.0, re.compile(r"\b(escape\w*|sanitize\w*|sanitise\w*|htmlspecialchars|htmlentities|encodeURI\w*|quote\w*|bleach|DOMPurify|purify|strip_tags|validate\w*|allow_?list|white_?list|deny_?list|black_?list)\b", IC)),
    Signal("deserialisation", 3.0, re.compile(r"\b(pickle|yaml\.(unsafe_)?load|unserialize|readObject|ObjectInputStream|XMLDecoder|BinaryFormatter|TypeNameHandling|Marshal\.load|fromXML|SnakeYAML|enableDefaultTyping|activateDefaultTyping|readResolve|serialVersionUID|resolveClass|ObjectMapper)\b", IC), "both"),
    Signal("xxe", 3.0, re.compile(r"external-general-entities|external-parameter-entities|disallow-doctype-decl|FEATURE_SECURE_PROCESSING|resolve_entities|XMLConstants\.ACCESS_EXTERNAL|setExpandEntityReferences|DOCTYPE|load-external-dtd|no_network", IC), "both"),
    Signal("crypto_tls", 2.0, re.compile(r"\b(verify(_mode|_peer|=|Hostname)?|ssl\w*|tls\w*|cert\w*|hostname_?verif\w*|cipher\w*|compare_digest|constant_time\w*|timingSafeEqual|hmac\w*|secrets\.|SecureRandom|random_bytes|urandom|CRYPTO_memcmp|nonce|iv\b)", IC), "both"),
    Signal("injection_sink", 2.0, re.compile(r"\b(exec\w*|system|popen|subprocess|shell\s*=\s*True|eval|Function\(|innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|Runtime\.getRuntime|ProcessBuilder|raw_?query|execute\w*|format\(|text\(|prepare\w*|bind\w*|parameteri[sz]\w*)\b", IC), "both"),
    Signal("redirect_ssrf", 2.0, re.compile(r"\b(redirect\w*|allowed_?hosts|is_safe_url|url_has_allowed_host|same_?origin|origin|referer|host_?header|ssrf|private_?ip|is_private|ip_?address|gethostbyname|getaddrinfo)\b", IC)),
    Signal("error_path", 1.0, re.compile(r"\b(return\s+(-\w+|-?1|NULL|nullptr|false|err\w*|E[A-Z]+|\w*(ERROR|FAIL|INVALID|DENIED|EINVAL)\w*)|raise\s+\w+|throw\s+new\s+\w+|throw\s+\w+|abort\(|panic\(|goto\s+(err|fail|out)\w*|\w*err(or)?_?code\s*=|\w*ERROR_\w+)", IC)),
    Signal("negative_check", 2.5, re.compile(r"\b(len|length|size|count|n|num|offset|idx|index|pos)\w*\s*(<\s*0\b|<=\s*-1\b|>=\s*0\b)", IC)),
    Signal("limit_constant", 1.0, re.compile(r"\b[A-Z][A-Z0-9_]*(MAX|LIMIT|LEN|SIZE|DEPTH|COUNT)[A-Z0-9_]*\b|\bmax_?(len|length|size|depth|count)\b", IC)),
    Signal("debug_branch_removed", 2.0, re.compile(r"\b(debug\w*|test_?mode|bypass\w*|backdoor|magic|hard_?coded|master_?(key|password)|skip_?(auth|verify|check)\w*|insecure\w*|unsafe\w*|TODO|FIXME|XXX)\b", IC), "removed"),
]

SECURITY_WORDS = re.compile(r"\b(security|secur|cve-\d{4}-\d+|ghsa-|vuln\w*|exploit|overflow|underflow|out[- ]of[- ]bounds|oob|use[- ]after[- ]free|uaf|double free|xss|csrf|ssrf|xxe|injection|traversal|rce|dos|denial of service|auth(entication|orisation|orization)? bypass|privilege|escalat\w*|sanitiz\w*|sanitis\w*|leak|disclosure|crash|harden\w*)\b", IC)
BLAND_WORDS = re.compile(r"\b(fix(es|ed)? (an? )?(edge|corner) cases?|refactor\w*|clean ?up|cleanup|minor|tweak\w*|improve\w*|robust\w*|small fix|misc|various|update|bump|adjust\w*|handle\w*|check\w*|validate\w*|correct\w*|polish)\b", IC)


def score_lines(added: list[str], removed: list[str]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for sig in SIGNALS:
        lines = added if sig.side == "added" else removed if sig.side == "removed" else added + removed
        n = sum(1 for ln in lines if sig.pattern.search(ln))
        if n and sig.side == "both" and _same_tokens(added, removed, sig):
            continue
        if n:
            hits[sig.name] = n
    return hits


def _same_tokens(added: list[str], removed: list[str], sig: Signal) -> bool:
    """A 'both' signal that merely moved (identical matched lines on both sides) is not a change."""
    a = sorted(ln.strip() for ln in added if sig.pattern.search(ln))
    r = sorted(ln.strip() for ln in removed if sig.pattern.search(ln))
    return a == r


def weight_of(hits: dict[str, int]) -> float:
    w = {s.name: s.weight for s in SIGNALS}
    return sum(w[k] * min(v, 3) ** 0.5 for k, v in hits.items())


def combine(hits: dict[str, int], changed_lines: int, messages: list[str]) -> tuple[float, dict[str, object]]:
    base = weight_of(hits)
    if not hits:
        return 0.0, {"hits": {}}
    focus = 1.6 if changed_lines <= 12 else 1.25 if changed_lines <= 40 else 1.0 if changed_lines <= 150 else 0.6
    if "copy_alloc_site" in hits and ({"bounds_check", "overflow_guard", "null_check"} & hits.keys()):
        base += 2.5
    if "error_path" in hits and len(hits) >= 2:
        base += 1.0
    text = "\n".join(messages)
    says_security = bool(SECURITY_WORDS.search(text))
    bland = bool(text) and not says_security and bool(BLAND_WORDS.search(text))
    msg_bonus = 1.5 if bland else 1.0 if says_security else 0.0
    score = round(base * focus + msg_bonus, 2)
    return score, {"hits": hits, "focus": focus, "bland_message": bland, "message_says_security": says_security, "changed_lines": changed_lines}
