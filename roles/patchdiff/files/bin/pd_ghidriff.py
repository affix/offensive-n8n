"""Binary mode for pd_diff: ghidriff each changed target pair against a persistent per-product project."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pd_score import combine, score_lines
from pdlib import PD_HOME, GhidraLock, Stage, StageError, log, read_json, rmtree, run, safe_name

TOOLS = read_json(PD_HOME / "etc" / "tools.json", {}) or {}
REQUIRED_FLAGS = ["--engine", "--output-path", "--project-location", "--project-name", "--symbols-path", "--gzfs-path",
                  "--no-symbols", "--log-path", "--min-func-len", "--max-ram-percent", "--jvm-args", "--decompiler-timeout"]
SNIPPET_CAP = 6000
HELPER_CALLS = re.compile(r"(strn?len|wcs?n?len|memchr|strnlen_s|__memcpy_chk|__strcpy_chk|__sprintf_chk|__snprintf_chk|"
                          r"__read_chk|__fortify\w*|__stack_chk_fail|check\w*|valid\w*|bound\w*|sanit\w*|safe\w*|"
                          r"\w*overflow\w*|\w*_s$|strlcpy|strlcat|reallocarray|calloc)", re.I)
COPY_SITES = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|strcat|sprintf|vsprintf|snprintf|malloc|calloc|realloc|alloca|read|recv|fread)\b")
NUM = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d{2,}\b")


def ghidriff_cmd() -> list[str]:
    return [sys.executable, "-m", "ghidriff"]


def check_flags() -> None:
    out = run([*ghidriff_cmd(), "--help"], timeout=120).stdout
    missing = [f for f in REQUIRED_FLAGS if f not in out]
    if missing:
        raise StageError(f"installed ghidriff lacks flags {missing}; check the pinned version")


def env_for_ghidra() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GHIDRA_INSTALL_DIR", TOOLS.get("ghidra_install_dir", "/opt/ghidra/current"))
    if not Path(env["GHIDRA_INSTALL_DIR"], "Ghidra").is_dir():
        raise StageError(f"GHIDRA_INSTALL_DIR {env['GHIDRA_INSTALL_DIR']} is not a Ghidra install")
    return env


def stage_pair(st: Stage, pair: dict[str, Any], work: Path) -> tuple[Path, Path, str]:
    """Copy the pair under one stable basename so project and program names repeat across releases."""
    base = safe_name(Path(pair["key"].replace("{v}", "")).name or "target", 60)
    tag = hashlib.sha1(pair["key"].encode()).hexdigest()[:8]
    paths = []
    for side in ("old", "new"):
        d = work / "in" / side / tag
        d.mkdir(parents=True, exist_ok=True)
        dst = d / base
        shutil.copyfile(pair[side], dst)
        paths.append(dst)
    return paths[0], paths[1], f"pd-{tag}"


def changed_constants(added: list[str], removed: list[str]) -> int:
    """Lines that differ only in a numeric literal: size or limit constants that moved."""
    strip = lambda s: NUM.sub("#", s.strip())  # noqa: E731
    rem = {strip(r): r for r in removed if NUM.search(r)}
    return sum(1 for a in added if NUM.search(a) and strip(a) in rem and rem[strip(a)].strip() != a.strip())


def score_function(m: dict[str, Any], added_strings: dict[str, list[str]]) -> tuple[float, dict[str, Any], list[str], list[str]]:
    diff = m.get("diff") or ""
    lines = diff.splitlines()[2:]
    added = [ln[1:] for ln in lines if ln.startswith("+")]
    removed = [ln[1:] for ln in lines if ln.startswith("-")]
    hits = score_lines(added, removed)
    new_calls = sorted(set(m["new"].get("called") or []) - set(m["old"].get("called") or []))
    helper_calls = [c for c in new_calls if HELPER_CALLS.search(str(c))]
    if helper_calls:
        hits["new_helper_calls"] = len(helper_calls)
    branches = sum(1 for a in added if re.search(r"\b(if|while|switch)\s*\(", a)) - sum(1 for r in removed if re.search(r"\b(if|while|switch)\s*\(", r))
    if branches > 0:
        hits["added_branches"] = branches
    if any(COPY_SITES.search(x) for x in added + removed) and branches > 0:
        hits["branch_near_copy"] = 1
    consts = changed_constants(added, removed)
    if consts:
        hits["size_constant_changed"] = consts
    strs = added_strings.get(m["new"].get("fullname") or m["new"].get("name"), [])
    if strs:
        hits["new_error_strings"] = len(strs)
    extra = {"new_helper_calls": 2.0, "added_branches": 1.5, "branch_near_copy": 2.5, "size_constant_changed": 2.0, "new_error_strings": 1.5}
    base_hits = {k: v for k, v in hits.items() if k not in extra}
    score, sig = combine(base_hits, len(added) + len(removed), [])
    score += sum(extra[k] * min(v, 3) ** 0.5 for k, v in hits.items() if k in extra)
    sim = float(m.get("ratio") or 0)
    score *= 1.0 + max(0.0, 0.98 - sim)
    sig["hits"] = hits
    sig.update({"ratio": sim, "i_ratio": m.get("i_ratio"), "b_ratio": m.get("b_ratio"), "diff_type": m.get("diff_type")})
    return round(score, 2), sig, new_calls, strs


def strings_by_function(pdiff: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for s in (pdiff.get("strings") or {}).get("added") or []:
        text = str(s.get("name") or "")[:200]
        for fn in s.get("calling") or []:
            out.setdefault(str(fn), []).append(text)
    return out


def run_ghidriff_pairs(st: Stage, targets: dict[str, Any], stable_key: Callable[..., str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pairs = [p for p in targets.get("pairs", []) if not p.get("identical") and not p.get("skipped")]
    if not pairs:
        return [], {"targets": 0, "note": "no changed binary targets"}
    check_flags()
    env = env_for_ghidra()
    threshold = float(st.cfg("similarity_threshold", 0.98))
    per_target_min = st.cfg_int("per_target_timeout_min", 90, 5, 600)
    min_len = st.cfg_int("min_func_len", 10, 1, 1000)
    proj = st.ghidra_dir
    proj.mkdir(parents=True, exist_ok=True)
    work = st.job_dir / "ghidriff"
    kind = st.cfg("artefact_kind", "")
    results: list[dict[str, Any]] = []
    target_notes: list[dict[str, Any]] = []
    with GhidraLock(f"{st.product} {st.old}->{st.new}", wait_s=st.cfg_int("ghidra_lock_wait_min", 60, 0, 720) * 60):
        for pair in pairs:
            old, new, name = stage_pair(st, pair, work)
            out = work / "out" / name
            rmtree(out)
            out.mkdir(parents=True)
            cmd = [
                *ghidriff_cmd(), "--engine", "VersionTrackingDiff", "--output-path", str(out),
                "--project-location", str(proj), "--project-name", name,
                "--symbols-path", str(proj / "symbols"), "--gzfs-path", str(work / "gzfs"),
                "--log-path", str(out / "ghidriff.log"), "--min-func-len", str(min_len),
                "--max-ram-percent", str(TOOLS.get("ghidriff_max_ram_percent", 60)),
                f"--jvm-args=-Xmx{TOOLS.get('ghidra_maxmem', '4g')}",
                "--decompiler-timeout", str(st.cfg_int("decompiler_timeout_s", 60, 10, 600)),
            ]
            if kind != "pe":
                cmd.append("--no-symbols")
            cmd += [str(old), str(new)]
            log(f"ghidriff {pair['key']} (timeout {per_target_min}m)")
            try:
                r = run(cmd, timeout=per_target_min * 60, check=False, env=env)
            except subprocess.TimeoutExpired:
                st.warn(f"{pair['key']}: ghidriff timed out after {per_target_min}m, skipped")
                target_notes.append({"key": pair["key"], "status": "timeout"})
                continue
            (out / "stdout.log").write_text((r.stdout or "")[-200000:] + (r.stderr or "")[-200000:])
            jpath = out / "json" / f"{old.name}-{new.name}.ghidriff.json"
            if r.returncode != 0 or not jpath.is_file():
                st.warn(f"{pair['key']}: ghidriff rc={r.returncode}, no JSON; see {out}/stdout.log")
                target_notes.append({"key": pair["key"], "status": f"failed rc={r.returncode}"})
                continue
            pdiff = read_json(jpath, {})
            stats = pdiff.get("stats", {})
            strs = strings_by_function(pdiff)
            modified = (pdiff.get("functions") or {}).get("modified") or []
            kept = 0
            for m in modified:
                if float(m.get("ratio") or 0) >= threshold or "code" not in (m.get("diff_type") or []):
                    continue
                score, sig, new_calls, new_strs = score_function(m, strs)
                fn = m["new"].get("fullname") or m["new"].get("name") or "?"
                kept += 1
                results.append({
                    "key": stable_key(st.product, st.old, st.new, "function", pair["key"], fn),
                    "kind": "function", "location": f"{pair['key']}!{fn}", "file": pair["key"], "function": fn,
                    "address": {"old": m["old"].get("address"), "new": m["new"].get("address")},
                    "score": score, "signals": sig, "new_calls": new_calls[:20], "new_strings": new_strs[:10],
                    "snippet": (m.get("diff") or "")[:SNIPPET_CAP], "truncated": len(m.get("diff") or "") > SNIPPET_CAP,
                    "ghidriff_json": str(jpath),
                })
            target_notes.append({"key": pair["key"], "status": "ok", "modified": len(modified), "kept": kept,
                                 "added_funcs": stats.get("added_funcs_len"), "deleted_funcs": stats.get("deleted_funcs_len"),
                                 "similarity": stats.get("match_func_similarity_percent")})
            rmtree(work / "gzfs")
    results.sort(key=lambda c: c["score"], reverse=True)
    top = results[: st.cfg_int("top_n", 20, 1, 100)]
    return top, {"targets": len(pairs), "functions_scored": len(results), "target_status": target_notes[:50],
                 "similarity_threshold": threshold, "only_new_binaries": targets.get("only_new", [])[:20]}
