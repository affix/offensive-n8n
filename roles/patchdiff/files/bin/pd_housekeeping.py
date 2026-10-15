"""PD housekeeping: compress old runs, prune unreferenced cache versions, clear stale locks, report disk and images."""

from __future__ import annotations

import argparse
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Any

from pdlib import (
    GHIDRA_LOCK, JOB_DIR_RE, MB, PD_HOME, PD_ROOT, GhidraLock, StageError, log, read_json, rmtree, run, run_main,
    safe_name, tree_size, write_json,
)

RUN_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{4}$")
RUN_TGZ_RE = re.compile(r"^(\d{8}T\d{6}Z-[0-9a-f]{4})\.tar\.gz$")
RESERVED = {"pd-sys"}
LOCK_STALE_MIN = 960


def products() -> list[Path]:
    return sorted(p for p in PD_ROOT.iterdir() if p.is_dir() and not p.name.startswith((".", "_")) and p.name not in RESERVED)


def run_index(prod: Path) -> list[dict[str, Any]]:
    """Runs (dir or tarball) with their versions; tarballs rely on the index written before compression."""
    idx_path = prod / ".runs.json"
    idx = {r["run_id"]: r for r in read_json(idx_path, []) or []}
    for d in prod.iterdir():
        if d.is_dir() and RUN_RE.match(d.name):
            cfg = read_json(d / "config.json", {}) or {}
            idx[d.name] = {"run_id": d.name, "old": cfg.get("old_version"), "new": cfg.get("new_version")}
    write_json(idx_path, sorted(idx.values(), key=lambda r: r["run_id"]), indent=1)
    return sorted(idx.values(), key=lambda r: r["run_id"])


def compress_runs(prod: Path, keep_days: int, issues: list[str]) -> int:
    runs = sorted(d for d in prod.iterdir() if d.is_dir() and RUN_RE.match(d.name))
    if (prod / ".lock").exists():
        return 0
    cutoff = time.time() - keep_days * 86400
    done = 0
    for d in runs[:-1]:
        if d.stat().st_mtime > cutoff:
            continue
        tgz = prod / f"{d.name}.tar.gz"
        tmp = prod / f".{d.name}.tar.gz.tmp"
        try:
            with tarfile.open(tmp, "w:gz", compresslevel=6) as tf:
                tf.add(d, arcname=d.name)
            tmp.rename(tgz)
            rmtree(d)
            done += 1
        except OSError as e:
            tmp.unlink(missing_ok=True)
            issues.append(f"{prod.name}/{d.name}: compress failed: {e}")
    return done


def prune_cache(prod: Path, runs: list[dict[str, Any]], keep_runs: int) -> list[str]:
    cache = PD_ROOT / "_cache" / prod.name
    if not cache.is_dir():
        return []
    keep = {safe_name(str(v)) for r in runs[-keep_runs:] for v in (r.get("old"), r.get("new")) if v}
    if not keep:
        return []
    pruned = []
    for v in cache.iterdir():
        if v.is_dir() and v.name != "repo.git" and v.name not in keep:
            rmtree(v)
            pruned.append(v.name)
    return pruned


def clear_stale_locks(issues: list[str]) -> list[str]:
    cleared = []
    for prod in products():
        lock = prod / ".lock"
        if lock.is_dir() and (time.time() - lock.stat().st_mtime) / 60 > LOCK_STALE_MIN:
            rmtree(lock)
            cleared.append(f"{prod.name}/.lock")
    if GHIDRA_LOCK.exists() and GhidraLock("housekeeping")._stale():
        info = read_json(GHIDRA_LOCK / "owner.json", {})
        rmtree(GHIDRA_LOCK)
        cleared.append(f".ghidra.lock ({info.get('owner')})")
    # Per-run worker SSH keys live in RAM; PD · Worker removes them on teardown, this catches runs that died first.
    ssh_root = Path("/dev/shm/pd-ssh")
    if ssh_root.is_dir():
        for d in ssh_root.iterdir():
            if d.is_dir() and not d.is_symlink() and (time.time() - d.stat().st_mtime) / 3600 > 26:
                rmtree(d)
                cleared.append(f"worker key {d.name}")
    if cleared:
        issues.append(f"cleared stale locks: {', '.join(cleared)}")
    return cleared


def check_images(issues: list[str]) -> dict[str, bool]:
    tools = read_json(PD_HOME / "etc" / "tools.json", {}) or {}
    status = {}
    for key in ("unblob_image", "ilspy_image"):
        ref = tools.get(key)
        if not ref:
            continue
        ok = run(["docker", "image", "inspect", "--format", "{{.Id}}", ref], check=False, timeout=60).returncode == 0
        status[ref] = ok
        if not ok:
            issues.append(f"pinned image missing locally: {ref} (re-run the patchdiff role)")
    return status


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--job-dir", required=True)
    p.add_argument("--keep-days", type=int, default=14)
    p.add_argument("--keep-runs", type=int, default=3)
    p.add_argument("--min-free-gb", type=int, default=10)
    args = p.parse_args()
    job = Path(args.job_dir)
    if not JOB_DIR_RE.match(str(job)) or job.parent.parent.name != "pd-sys":
        raise StageError(f"refusing job dir {job}")
    job.mkdir(parents=True, exist_ok=True)
    issues: list[str] = []
    cleared = clear_stale_locks(issues)
    report: dict[str, Any] = {}
    for prod in products():
        runs = run_index(prod)
        compressed = compress_runs(prod, args.keep_days, issues)
        pruned = prune_cache(prod, runs, args.keep_runs)
        gdir = PD_ROOT / "_ghidra" / prod.name
        report[prod.name] = {
            "runs": len(runs), "compressed": compressed, "cache_pruned": pruned,
            "cache_mb": tree_size(PD_ROOT / "_cache" / prod.name) // MB,
            "ghidra_mb": tree_size(gdir) // MB if gdir.exists() else 0,
            "runs_mb": tree_size(prod) // MB,
        }
        log(f"{prod.name}: {report[prod.name]}")
    du = shutil.disk_usage(PD_ROOT)
    free_gb = du.free // (1024 ** 3)
    free_pct = round(100 * du.free / du.total, 1)
    if free_gb < args.min_free_gb or free_pct < 10:
        issues.append(f"low disk on {PD_ROOT}: {free_gb}GB free ({free_pct}%)")
    for name, r in report.items():
        if r["ghidra_mb"] > 20480:
            issues.append(f"{name}: Ghidra project is {r['ghidra_mb'] // 1024}GB")
    images = check_images(issues)
    sys_root = PD_ROOT / "pd-sys"
    old_sys = sorted(d for d in sys_root.iterdir() if d.is_dir() and RUN_RE.match(d.name))[:-20] if sys_root.is_dir() else []
    for d in old_sys:
        rmtree(d)
    write_json(job / "result.json", {
        "stage": "housekeeping", "issues": issues, "products": report, "locks_cleared": cleared, "images": images,
        "disk": {"free_gb": free_gb, "free_pct": free_pct, "total_gb": du.total // (1024 ** 3)},
        "pd_root_mb": tree_size(PD_ROOT) // MB,
    })
    return 0


if __name__ == "__main__":
    run_main(main)
