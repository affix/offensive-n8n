"""PD diff stage: source hunks (git or decompiled trees) or ghidriff function diffs -> candidates.json."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from unidiff import PatchSet

from pd_score import combine, score_lines
from pdlib import (
    Stage, StageError, base_parser, glob_match, init_stage, log, read_json, run, run_main, write_json,
)

GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "diff.noprefix=false"]
DEFAULT_EXCLUDES = [
    "**/test/**", "**/tests/**", "**/testing/**", "**/__tests__/**", "**/spec/**", "**/specs/**", "**/testdata/**",
    "**/fixtures/**", "**/*_test.*", "**/*_tests.*", "**/test_*.py", "**/*Test.java", "**/*Tests.cs", "**/*.spec.*", "**/*.test.*",
    "**/docs/**", "**/doc/**", "**/*.md", "**/*.rst", "**/*.adoc", "**/*.txt", "**/CHANGELOG*", "**/CHANGES*", "**/NEWS*", "**/HISTORY*", "**/Changes", "**/ChangeLog*",
    "**/vendor/**", "**/third_party/**", "**/third-party/**", "**/3rdparty/**", "**/node_modules/**", "**/external/**", "**/deps/**",
    "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/Cargo.lock", "**/go.sum", "**/poetry.lock", "**/uv.lock",
    "**/composer.lock", "**/Gemfile.lock", "**/*.min.js", "**/*.min.css", "**/*.map", "**/*.pb.go", "**/*_pb2.py", "**/*.pb.cc",
    "**/*.pb.h", "**/generated/**", "**/*.generated.*", "**/*_generated.*", "**/dist/**", "**/build/**", "**/*.po", "**/*.pot",
    "**/locale/**", "**/locales/**", "**/i18n/**", "**/*.svg", "**/*.png", "**/*.jpg", "**/*.gif", "**/*.ico", "**/*.snap",
    "**/.github/**", "**/.gitlab-ci.yml", "**/*.lock", "**/version.*", "**/VERSION",
]
# Decompiled trees are package paths (com/acme/build/..., .../external/...), so the repo-oriented list above would drop real code.
DECOMPILED_EXCLUDES = ["**/META-INF/**", "**/Properties/AssemblyInfo.cs", "**/*.csproj", "**/BuildConfig.java", "**/R.java"]
SNIPPET_CAP = 6000
# Build and config files rarely carry the fix itself; keep them but rank them down.
BUILD_FILES = re.compile(r"(^|/)(Makefile[^/]*|CMakeLists\.txt|configure(\.ac|\.in)?|meson\.build|[^/]*\.(am|in|m4|cmake|gradle|ya?ml|toml|cfg|ini|sh|bat|ps1|mk|bazel|bzl)|pom\.xml|Dockerfile[^/]*|buildconf[^/]*)$", re.I)
BUILD_WEIGHT = 0.3


def stable_key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


# --- Source mode ---------------------------------------------------------------


def git(repo: Path, args: list[str], timeout: int = 1800) -> str:
    return run(["git", *GIT_SAFE, "--git-dir", str(repo), *args], timeout=timeout,
               env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).stdout


def parse_hunks(diff_text: str, strip: tuple[str, str] | None, excludes: list[str]) -> tuple[list[dict[str, Any]], int, int]:
    patch = PatchSet(diff_text)
    hunks: list[dict[str, Any]] = []
    files_seen = files_excluded = 0
    for pf in patch:
        if pf.is_binary_file:
            continue
        path = pf.path
        if strip:
            for prefix in strip:
                if path.startswith(prefix):
                    path = path[len(prefix):].lstrip("/")
        files_seen += 1
        if glob_match(path, excludes):
            files_excluded += 1
            continue
        for h in pf:
            added = [ln.value.rstrip("\n") for ln in h if ln.is_added]
            removed = [ln.value.rstrip("\n") for ln in h if ln.is_removed]
            if not added and not removed:
                continue
            hunks.append({
                "file": path, "func": (h.section_header or "").strip()[:200],
                "new_start": h.target_start, "new_len": h.target_length, "old_start": h.source_start,
                "added": added, "removed": removed, "text": str(h),
                "added_lines": [ln.target_line_no for ln in h if ln.is_added],
            })
    return hunks, files_seen, files_excluded


def blame_commits(repo: Path, new: str, file: str, lines: list[int], in_range: set[str]) -> list[str]:
    if not lines:
        return []
    lo, hi = min(lines), max(lines)
    r = run(["git", *GIT_SAFE, "--git-dir", str(repo), "blame", "--porcelain", "-L", f"{lo},{hi}", new, "--", file],
            check=False, timeout=300)
    shas = {ln.split()[0] for ln in r.stdout.splitlines() if re.match(r"^[0-9a-f]{40} \d+ \d+", ln)}
    return sorted(shas & in_range)


def source_candidates(st: Stage, targets: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    excludes = st.cfg_list("source_exclude_globs", DEFAULT_EXCLUDES if targets["mode"] == "git" else DECOMPILED_EXCLUDES)
    extra = st.cfg_list("source_exclude_extra", [])
    excludes = excludes + extra
    meta: dict[str, Any] = {}
    if targets["mode"] == "git":
        repo = Path(targets["repo"])
        old, new = targets["old"]["commit"], targets["new"]["commit"]
        diff_text = git(repo, ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--find-renames", "-U5", f"{old}..{new}"], timeout=3600)
        hunks, seen, excl = parse_hunks(diff_text, None, excludes)
        in_range = set(git(repo, ["rev-list", f"{old}..{new}"]).split())
        meta = {"commits_in_range": len(in_range)}
    else:
        old_dir, new_dir = targets["old_dir"], targets["new_dir"]
        r = run(["git", *GIT_SAFE, "diff", "--no-index", "--no-color", "--no-ext-diff", "-U5", old_dir, new_dir], check=False, timeout=3600)
        if r.returncode not in (0, 1):
            raise StageError(f"git diff --no-index failed: {r.stderr[-800:]}")
        hunks, seen, excl = parse_hunks(r.stdout, (old_dir.lstrip("/"), new_dir.lstrip("/")), excludes)
        in_range, repo, new = set(), None, ""
    log(f"{len(hunks)} hunks across {seen} files ({excl} excluded)")

    scored: list[dict[str, Any]] = []
    for h in hunks:
        hits = score_lines(h["added"], h["removed"])
        if not hits:
            continue
        score, sig = combine(hits, len(h["added"]) + len(h["removed"]), [])
        if BUILD_FILES.search(h["file"]):
            score, sig["build_file"] = round(score * BUILD_WEIGHT, 2), True
        scored.append({**h, "score": score, "signals": sig})
    scored.sort(key=lambda c: c["score"], reverse=True)

    commit_cache: dict[str, dict[str, str]] = {}
    pool = scored[: max(st.cfg_int("top_n", 20, 1, 100) * 3, 60)]
    for c in pool:
        shas = blame_commits(repo, new, c["file"], c["added_lines"], in_range) if repo else []
        commits = []
        for sha in shas[:5]:
            if sha not in commit_cache:
                subj, _, body = git(repo, ["log", "-1", "--format=%s%x1f%b", sha]).partition("\x1f")
                commit_cache[sha] = {"sha": sha, "subject": subj.strip()[:300], "body": body.strip()[:1200]}
            commits.append(commit_cache[sha])
        c["commits"] = commits
        msgs = [f"{x['subject']}\n{x['body']}" for x in commits]
        build = c["signals"].get("build_file", False)
        c["score"], c["signals"] = combine(c["signals"]["hits"], c["signals"]["changed_lines"], msgs)
        if build:
            c["score"], c["signals"]["build_file"] = round(c["score"] * BUILD_WEIGHT, 2), True
    pool.sort(key=lambda c: c["score"], reverse=True)

    out = []
    for c in pool[: st.cfg_int("top_n", 20, 1, 100)]:
        loc = f"{c['file']}:{c['new_start']}"
        out.append({
            "key": stable_key(st.product, st.old, st.new, "source_hunk", c["file"], c["func"], hashlib.sha256(c["text"].encode()).hexdigest()),
            "kind": "source_hunk", "location": loc, "file": c["file"], "function": c["func"],
            "score": c["score"], "signals": c["signals"], "commits": c.get("commits", []),
            "snippet": c["text"][:SNIPPET_CAP], "truncated": len(c["text"]) > SNIPPET_CAP,
        })
    meta.update({"hunks_total": len(hunks), "hunks_with_signals": len(scored), "files_seen": seen, "files_excluded": excl})
    return out, meta


# --- Binary mode (ghidriff) ---------------------------------------------------


def binary_candidates(st: Stage, targets: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from pd_ghidriff import run_ghidriff_pairs

    return run_ghidriff_pairs(st, targets, stable_key)


def main() -> int:
    args = base_parser(__doc__ or "").parse_args()
    st = init_stage(args)
    targets = read_json(st.stage_dir("unpack") / "targets.json")
    if not targets:
        raise StageError("unpack/targets.json missing; run unpack first")
    if targets["mode"] in {"git", "dir"}:
        cands, meta = source_candidates(st, targets)
    else:
        cands, meta = binary_candidates(st, targets)
    for i, c in enumerate(cands, 1):
        c["rank"] = i
    write_json(st.job_dir / "candidates.json", cands, indent=1)
    st.write_result({
        "mode": targets["mode"], "candidates": len(cands), "top_score": cands[0]["score"] if cands else 0,
        "top": [{"rank": c["rank"], "location": c["location"], "score": c["score"]} for c in cands[:5]],
        "candidates_path": str(st.job_dir / "candidates.json"), **meta,
    })
    return 0


if __name__ == "__main__":
    run_main(main)
