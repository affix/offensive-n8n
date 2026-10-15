"""PD triage stage: ask the local Ollama model about each shortlisted candidate. Advisory only, never drops a candidate."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import httpx

from pdlib import PD_HOME, StageError, base_parser, init_stage, log, read_json, run_main, write_json

TOOLS = read_json(PD_HOME / "etc" / "tools.json", {}) or {}
SYSTEM = "\n".join([
    "You are a vulnerability researcher reviewing one change between two releases of a product, looking for security fixes.",
    "You get the before/after code (source hunk or decompiled function diff), its location, the commit message if known, and any advisory text.",
    "Judge only from the evidence given. Reply with JSON only, exactly this shape:",
    '{"bug_class": "<CWE-style class or none>", "likely_security_fix": <integer 0-100>, "summary": "<one line, max 30 words>",'
    ' "entry_point_guess": "<how attacker input reaches this code, or unknown>", "confidence": "<low|medium|high>"}',
    "likely_security_fix: 0 means certainly not a security fix (refactor, feature, logging), 100 means certainly fixes an exploitable bug.",
    "Added bounds/length checks before copies, new auth/permission checks, path normalisation and new input validation are strong signals.",
])


def prompt_for(c: dict[str, Any], product: str, old: str, new: str) -> str:
    commits = "\n".join(f"- {x.get('subject', '')}: {x.get('body', '')[:400]}" for x in c.get("commits", [])[:3]) or "unknown"
    extra = []
    if c.get("new_calls"):
        extra.append(f"New calls: {', '.join(map(str, c['new_calls'][:10]))}")
    if c.get("new_strings"):
        extra.append(f"New strings: {' | '.join(map(str, c['new_strings'][:5]))}")
    return "\n".join([
        f"Product: {product} {old} -> {new}",
        f"Kind: {c.get('kind')}  Location: {c.get('location')}",
        f"Heuristic signals: {json.dumps((c.get('signals') or {}).get('hits', {}))}",
        f"Commits:\n{commits}",
        *extra,
        f"Advisory text: {(c.get('advisory_text') or 'none')[:1500]}",
        "Diff:",
        (c.get("snippet") or "")[:5000],
    ])


def ask(client: httpx.Client, url: str, model: str, user: str) -> dict[str, Any]:
    body = {
        "model": model, "stream": False, "think": False, "format": "json", "keep_alive": "15m",
        "options": {"temperature": 0.1, "num_predict": 400},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
    }
    r = client.post(url, json=body)
    r.raise_for_status()
    text = (r.json().get("message") or {}).get("content") or ""
    m = re.search(r"\{[\s\S]*\}", text)
    p = json.loads(m.group(0) if m else text)
    try:
        score = max(0, min(100, int(p.get("likely_security_fix"))))
    except (TypeError, ValueError):
        score = None
    conf = str(p.get("confidence") or "").lower()
    return {
        "llm_bug_class": str(p.get("bug_class") or "")[:120],
        "llm_likely_security_fix": score,
        "llm_summary": re.sub(r"\s+", " ", str(p.get("summary") or "")).strip()[:300],
        "llm_entry_point": str(p.get("entry_point_guess") or "")[:300],
        "llm_confidence": conf if conf in {"low", "medium", "high"} else "",
    }


def main() -> int:
    p = base_parser(__doc__ or "")
    p.add_argument("--max", type=int, default=25)
    args = p.parse_args()
    st = init_stage(args)
    src = st.stage_dir("advisory") / "candidates.json"
    cands = read_json(src)
    if cands is None:
        src = st.stage_dir("diff") / "candidates.json"
        cands = read_json(src)
        st.warn("advisory candidates missing, triaging raw diff candidates")
    if cands is None:
        raise StageError("no candidates.json from advisory or diff")
    base = st.cfg("triage_ollama_url") or TOOLS.get("ollama_url", "http://10.20.0.2:11434")
    model = st.cfg("triage_ollama_model") or TOOLS.get("ollama_model", "huihui_ai/qwen3.5-abliterated:9b")
    if not base or not model:
        raise StageError("triage: ollama url/model not configured")
    url = f"{base.rstrip('/')}/api/chat"
    log(f"triage -> {url} ({model})")
    limit = max(1, min(args.max, 25))
    ok = failed = 0
    with httpx.Client(timeout=httpx.Timeout(30, read=180)) as client:
        for c in cands[:limit]:
            t0 = time.time()
            try:
                c.update(ask(client, url, model, prompt_for(c, st.product, st.old, st.new)))
                ok += 1
            except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
                c.update({"llm_bug_class": "", "llm_likely_security_fix": None, "llm_summary": "triage unavailable",
                          "llm_entry_point": "", "llm_confidence": ""})
                st.warn(f"{c.get('location')}: {type(e).__name__}: {str(e)[:200]}")
                failed += 1
            log(f"{c.get('location')}: {c.get('llm_likely_security_fix')} {c.get('llm_bug_class')} ({time.time() - t0:.0f}s)")
    write_json(st.job_dir / "triaged.json", cands, indent=1)
    st.write_result({"triaged": ok, "failed": failed, "candidates": len(cands), "model": model,
                     "triaged_path": str(Path(st.job_dir / "triaged.json"))})
    return 0


if __name__ == "__main__":
    run_main(main)
