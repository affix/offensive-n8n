"""Shared helpers for the pd_* stage scripts.

Contract every stage follows:
  - args: --job-dir, --product, --old, --new (+ stage-specific)
  - config: <run_dir>/config.json, written by the PD Orchestrator
  - output: <job_dir>/result.json (small), everything else on disk
  - exit 0 on success, non-zero on failure, never 124 (reserved for timeout)
"""

from __future__ import annotations

import argparse
import bz2
import fnmatch
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

PD_ROOT = Path(os.environ.get("PD_ROOT", "/opt/loot/patchdiff"))
PD_HOME = Path(os.environ.get("PD_HOME", "/opt/patchdiff"))
JOB_DIR_RE = re.compile(r"^/opt/loot/patchdiff/[a-z0-9][a-z0-9_-]{0,39}/\d{8}T\d{6}Z-[0-9a-f]{4}/[a-z_]{2,20}$")
PRODUCT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$")
GHIDRA_LOCK = PD_ROOT / ".ghidra.lock"
GHIDRA_LOCK_STALE_MIN = 780
MB = 1024 * 1024


class StageError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


@dataclass
class Stage:
    job_dir: Path
    run_dir: Path
    product: str
    old: str
    new: str
    config: dict[str, Any]
    args: argparse.Namespace
    warnings: list[str] = field(default_factory=list)

    @property
    def cache_dir(self) -> Path:
        return PD_ROOT / "_cache" / self.product

    @property
    def inbox_dir(self) -> Path:
        return PD_ROOT / "_inbox" / self.product

    @property
    def ghidra_dir(self) -> Path:
        return PD_ROOT / "_ghidra" / self.product

    def stage_dir(self, name: str) -> Path:
        return self.run_dir / name

    def cfg(self, key: str, default: Any = None) -> Any:
        v = self.config.get(key)
        return default if v is None or v == "" else v

    def cfg_int(self, key: str, default: int, lo: int, hi: int) -> int:
        try:
            v = int(self.config.get(key) or default)
        except (TypeError, ValueError):
            v = default
        return max(lo, min(hi, v))

    def cfg_list(self, key: str, default: list[str] | None = None) -> list[str]:
        v = self.config.get(key)
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            if v.strip().startswith("["):
                try:
                    return [str(x).strip() for x in json.loads(v) if str(x).strip()]
                except json.JSONDecodeError:
                    pass
            return [x.strip() for x in re.split(r"[,\n]", v) if x.strip()]
        return list(default or [])

    def warn(self, msg: str) -> None:
        log(f"WARN {msg}")
        self.warnings.append(msg)

    def write_result(self, data: dict[str, Any]) -> None:
        out = {"stage": self.job_dir.name, "product": self.product, "old": self.old, "new": self.new, **data}
        if self.warnings:
            out["warnings"] = self.warnings[:50]
        write_json(self.job_dir / "result.json", out)


def base_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--job-dir", required=True)
    p.add_argument("--product", required=True)
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)
    return p


def init_stage(args: argparse.Namespace, clean: bool = True) -> Stage:
    job_dir = Path(args.job_dir)
    if not JOB_DIR_RE.match(str(job_dir)):
        raise StageError(f"refusing job dir {job_dir}")
    if not PRODUCT_RE.match(args.product):
        raise StageError(f"invalid product {args.product!r}")
    for v in (args.old, args.new):
        if not VERSION_RE.match(v):
            raise StageError(f"invalid version {v!r}")
    run_dir = job_dir.parent
    if run_dir.parent.name != args.product:
        raise StageError(f"job dir {job_dir} is not under product {args.product}")
    cfg_path = run_dir / "config.json"
    if not cfg_path.is_file():
        raise StageError(f"missing {cfg_path}")
    config = json.loads(cfg_path.read_text())
    if config.get("product") != args.product:
        raise StageError(f"config.json is for {config.get('product')!r}, not {args.product!r}")
    job_dir.mkdir(parents=True, exist_ok=True)
    if clean:
        for child in job_dir.iterdir():
            if child.name in {"job.sh", "job.log", ".done"}:
                continue
            rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
    return Stage(job_dir, run_dir, args.product, args.old, args.new, config, args)


def run_main(fn) -> None:
    """Run a stage entry point; map exceptions to exit 1 (never 124)."""
    try:
        rc = fn()
    except StageError as e:
        log(f"ERROR {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    sys.exit(0 if rc in (None, 0) else (1 if rc == 124 else int(rc)))


def write_json(path: Path, data: Any, indent: int | None = None) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=indent, ensure_ascii=False, default=str) + "\n")
    os.replace(tmp, path)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(MB), b""):
            h.update(chunk)
    return h.hexdigest()


def rmtree(path: Path) -> None:
    def onexc(func, p, _exc):
        os.chmod(p, stat.S_IRWXU)
        func(p)

    if path.exists():
        shutil.rmtree(path, onexc=onexc)


def tree_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def safe_name(s: str, limit: int = 80) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._")[:limit] or "x"


def version_vars(product: str, version: str) -> dict[str, str]:
    parts = re.split(r"[.\-_]", version)
    return {
        "product": product,
        "version": version,
        "version_underscore": version.replace(".", "_"),
        "version_dash": version.replace(".", "-"),
        "version_nodot": version.replace(".", ""),
        "major": parts[0] if parts else version,
        "minor": parts[1] if len(parts) > 1 else "",
        "major_minor": ".".join(parts[:2]),
        "major_minor_patch": ".".join(parts[:3]),
    }


def render_template(template: str, product: str, version: str) -> str:
    out = template
    for k, v in version_vars(product, version).items():
        out = out.replace(f"{{{k}}}", v)
    if "{" in out and "}" in out and re.search(r"\{[a-z_]+\}", out):
        raise StageError(f"unresolved placeholder in template {template!r}")
    return out


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int | None = None, check: bool = True,
        capture: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    log(f"$ {' '.join(cmd)}")
    p = subprocess.Popen(
        cmd, cwd=cwd, env=env, text=True, start_new_session=True,
        stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None,
    )
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(p)
        p.communicate()
        raise
    cp = subprocess.CompletedProcess(cmd, p.returncode, out or "", err or "")
    if check and cp.returncode != 0:
        raise StageError(f"{cmd[0]} exited {cp.returncode}: {(cp.stderr or cp.stdout)[-1500:].strip()}")
    return cp


def kill_group(p: subprocess.Popen) -> None:
    try:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(timeout=15)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# --- Safe extraction ---------------------------------------------------------


def _safe_member(dest: Path, name: str) -> Path:
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise StageError(f"unsafe archive member {name!r}")
    target = (dest / pure).resolve()
    if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
        raise StageError(f"archive member escapes destination: {name!r}")
    return target


def extract_zip(src: Path, dest: Path, max_bytes: int, max_ratio: int = 200) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(src) as zf:
        infos = zf.infolist()
        declared = sum(i.file_size for i in infos)
        if declared > max_bytes:
            raise StageError(f"{src.name}: declared unpacked size {declared // MB}MB over cap {max_bytes // MB}MB")
        for info in infos:
            target = _safe_member(dest, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > max_ratio and info.file_size > 50 * MB:
                raise StageError(f"{src.name}: {info.filename} compression ratio looks like a bomb")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as fin, target.open("wb") as fout:
                for chunk in iter(lambda: fin.read(MB), b""):
                    written += len(chunk)
                    total += len(chunk)
                    if written > info.file_size + MB or total > max_bytes:
                        raise StageError(f"{src.name}: unpacked size over cap {max_bytes // MB}MB")
                    fout.write(chunk)
            target.chmod(0o640)
    return total


def extract_tar(src: Path | Any, dest: Path, max_bytes: int, label: str = "") -> int:
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    mode = "r:*"
    tf = tarfile.open(fileobj=src, mode="r|*") if hasattr(src, "read") else tarfile.open(src, mode)
    with tf:
        for m in tf:
            if not (m.isfile() or m.isdir()):
                continue
            _safe_member(dest, m.name)
            if m.isfile():
                total += m.size
                if total > max_bytes:
                    raise StageError(f"{label or src}: unpacked size over cap {max_bytes // MB}MB")
            m.mode = 0o750 if m.isdir() else 0o640
            m.uid = m.gid = os.getuid()
            tf.extract(m, dest, filter="data")
    return total


def extract_deb(src: Path, dest: Path, max_bytes: int) -> int:
    """Debian package: ar archive holding data.tar.*; extracted in Python, no maintainer scripts."""
    members = run(["ar", "t", str(src)]).stdout.split()
    data = next((m for m in members if m.startswith("data.tar")), None)
    if not data:
        raise StageError(f"{src.name}: no data.tar member")
    proc = subprocess.Popen(["ar", "p", str(src), data], stdout=subprocess.PIPE)
    try:
        assert proc.stdout is not None
        if data.endswith(".zst"):
            zstd = subprocess.Popen(["zstd", "-dc"], stdin=proc.stdout, stdout=subprocess.PIPE)
            assert zstd.stdout is not None
            size = extract_tar(zstd.stdout, dest, max_bytes, src.name)
            zstd.wait()
        else:
            size = extract_tar(proc.stdout, dest, max_bytes, src.name)
    finally:
        proc.wait()
    return size


RPM_LEAD = b"\xed\xab\xee\xdb"
RPM_HEADER = b"\x8e\xad\xe8\x01"


def _read_exact(fin: IO[bytes], n: int, label: str) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = fin.read(n - len(buf))
        if not chunk:
            raise StageError(f"{label}: truncated cpio payload")
        buf += chunk
    return bytes(buf)


def _copy_n(fin: IO[bytes], fout: IO[bytes] | None, n: int, label: str) -> None:
    while n > 0:
        chunk = _read_exact(fin, min(n, MB), label)
        if fout is not None:
            fout.write(chunk)
        n -= len(chunk)


def extract_cpio(fin: IO[bytes], dest: Path, max_bytes: int, label: str) -> int:
    """newc/crc cpio stream; regular files and dirs only, hardlinks resolved, symlinks and devices skipped."""
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    links: dict[int, list[Path]] = {}
    while True:
        hdr = _read_exact(fin, 110, label)
        if hdr[:6] not in (b"070701", b"070702"):
            raise StageError(f"{label}: unsupported cpio header {hdr[:6]!r}")
        f = [int(hdr[6 + i * 8: 14 + i * 8], 16) for i in range(13)]
        ino, mode, nlink, size, namesize = f[0], f[1], f[4], f[6], f[11]
        name = _read_exact(fin, namesize, label)[:-1].decode("utf-8", "surrogateescape")
        _read_exact(fin, (4 - (110 + namesize) % 4) % 4, label)
        if name == "TRAILER!!!":
            break
        rel = name.removeprefix("./")
        ftype = stat.S_IFMT(mode)
        if ftype == stat.S_IFREG and rel:
            target = _safe_member(dest, rel)
            total += size
            if total > max_bytes:
                raise StageError(f"{label}: unpacked size over cap {max_bytes // MB}MB")
            target.parent.mkdir(parents=True, exist_ok=True)
            if nlink > 1 and size == 0:
                links.setdefault(ino, []).append(target)
            else:
                with target.open("wb") as fout:
                    _copy_n(fin, fout, size, label)
                target.chmod(0o640)
                for other in links.pop(ino, []):
                    shutil.copyfile(target, other)
                    other.chmod(0o640)
        else:
            if ftype == stat.S_IFDIR and rel:
                _safe_member(dest, rel).mkdir(parents=True, exist_ok=True)
            _copy_n(fin, None, size, label)
        _read_exact(fin, (4 - size % 4) % 4, label)
    return total


def _rpm_header_end(fh: IO[bytes], offset: int, align: bool, label: str) -> int:
    fh.seek(offset)
    head = fh.read(16)
    if len(head) != 16 or head[:4] != RPM_HEADER:
        raise StageError(f"{label}: bad RPM header at offset {offset}")
    nindex, hsize = struct.unpack(">II", head[8:16])
    end = offset + 16 + nindex * 16 + hsize
    return (end + 7) & ~7 if align else end


def rpm_tags(src: Path, wanted: set[int]) -> dict[int, list[str] | list[int]]:
    """Read INT32 and string-typed tags from the main RPM header (e.g. 1080-1082 for the changelog)."""
    out: dict[int, list[str] | list[int]] = {}
    with src.open("rb") as fh:
        if fh.read(4) != RPM_LEAD:
            raise StageError(f"{src.name}: not an RPM")
        offset = _rpm_header_end(fh, 96, True, src.name)
        fh.seek(offset + 8)
        nindex, hsize = struct.unpack(">II", fh.read(8))
        if nindex > 100_000 or hsize > 256 * MB:
            raise StageError(f"{src.name}: implausible RPM header size")
        index = fh.read(nindex * 16)
        store = fh.read(hsize)
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">iiii", index[i * 16: i * 16 + 16])
        if tag not in wanted or not 0 <= off < len(store):
            continue
        if typ == 4:
            out[tag] = list(struct.unpack(f">{count}i", store[off: off + 4 * count]))
        elif typ in (6, 8, 9):
            strings = store[off:].split(b"\0", count)[:count]
            out[tag] = [s.decode("utf-8", "replace") for s in strings]
    return out


def extract_rpm(src: Path, dest: Path, max_bytes: int) -> int:
    """RPM: lead, signature and main headers, then a compressed cpio payload; extracted in Python, no scriptlets."""
    with src.open("rb") as fh:
        if fh.read(4) != RPM_LEAD:
            raise StageError(f"{src.name}: not an RPM")
        offset = _rpm_header_end(fh, 96, True, src.name)
        offset = _rpm_header_end(fh, offset, False, src.name)
        fh.seek(offset)
        magic = fh.read(6)
    if magic.startswith(b"\x28\xb5\x2f\xfd"):
        with src.open("rb", buffering=0) as raw:
            raw.seek(offset)
            proc = subprocess.Popen(["zstd", "-dc"], stdin=raw, stdout=subprocess.PIPE)
            try:
                assert proc.stdout is not None
                return extract_cpio(proc.stdout, dest, max_bytes, src.name)
            finally:
                proc.kill()
                proc.wait()
    openers: dict[bytes, Any] = {b"\x1f\x8b": gzip.open, b"\xfd7zXZ": lzma.open, b"BZh": bz2.open, b"0707": lambda f: f}
    opener = next((o for m, o in openers.items() if magic.startswith(m)), None)
    if opener is None:
        raise StageError(f"{src.name}: unknown RPM payload compression {magic!r}")
    with src.open("rb") as fh:
        fh.seek(offset)
        return extract_cpio(opener(fh), dest, max_bytes, src.name)


# --- Globs and pairing -------------------------------------------------------


def glob_match(rel: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        pat = pat.lstrip("/")
        if fnmatch.fnmatchcase(rel, pat) or PurePosixPath(rel).match(pat):
            return True
        if pat.startswith("**/") and fnmatch.fnmatchcase(rel, pat[3:]):
            return True
    return False


def walk_files(root: Path) -> Iterator[str]:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p.relative_to(root).as_posix()


def normalise_rel(rel: str, version: str, extra: re.Pattern[str] | None = None) -> str:
    """Strip the version from a path so lib-1.2.3.so pairs with lib-1.2.4.so.

    Also strips the upstream part of a packaged version (7.4.2 from 1:7.4.2-3.el9), and anything `extra` matches.
    """
    out = rel
    variants = {version}
    base = re.split(r"[-+~]", version.split(":", 1)[-1])[0]
    if "." in base and len(base) >= 3:
        variants.add(base)
    for v in list(variants):
        variants |= {v.replace(".", "_"), v.replace(".", "-")}
    for v in sorted(variants, key=len, reverse=True):
        if v:
            out = out.replace(v, "{v}")
    if extra is not None:
        out = extra.sub("{v}", out)
    return out


# --- Ghidra lock --------------------------------------------------------------


class GhidraLock:
    """One Ghidra job per host: mkdir lock + owner file, stale after GHIDRA_LOCK_STALE_MIN or dead pid."""

    def __init__(self, owner: str, wait_s: int = 0) -> None:
        self.owner = owner
        self.wait_s = wait_s
        self.held = False

    def _stale(self) -> bool:
        info = read_json(GHIDRA_LOCK / "owner.json", {}) or {}
        pid = int(info.get("pid") or 0)
        age_min = (time.time() - GHIDRA_LOCK.stat().st_mtime) / 60
        if age_min > GHIDRA_LOCK_STALE_MIN:
            return True
        if pid and info.get("host") == os.uname().nodename:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False
        return False

    def __enter__(self) -> GhidraLock:
        deadline = time.time() + self.wait_s
        while True:
            try:
                GHIDRA_LOCK.mkdir()
                write_json(GHIDRA_LOCK / "owner.json", {"pid": os.getpid(), "host": os.uname().nodename, "owner": self.owner, "since": time.time()})
                self.held = True
                return self
            except FileExistsError as exc:
                if self._stale():
                    log(f"removing stale ghidra lock {read_json(GHIDRA_LOCK / 'owner.json', {})}")
                    rmtree(GHIDRA_LOCK)
                    continue
                if time.time() >= deadline:
                    raise StageError(f"ghidra lock held by {read_json(GHIDRA_LOCK / 'owner.json', {})}") from exc
                time.sleep(15)

    def __exit__(self, *_exc: object) -> None:
        if self.held:
            rmtree(GHIDRA_LOCK)
            self.held = False
