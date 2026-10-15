"""PD unpack stage: unpack both artefacts, pick diff targets with binary_globs, write targets.json."""

from __future__ import annotations

import gzip
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from pdlib import (
    MB, PD_HOME, RPM_LEAD, Stage, StageError, base_parser, extract_deb, extract_rpm, extract_tar, extract_zip, glob_match, init_stage,
    log, normalise_rel, read_json, rmtree, rpm_tags, run, run_main, safe_name, sha256_file, tree_size, walk_files, write_json,
)

TOOLS = read_json(PD_HOME / "etc" / "tools.json", {}) or {}
MAGIC = {b"\x7fELF": "elf", b"MZ": "pe", b"\xcf\xfa\xed\xfe": "macho", b"\xce\xfa\xed\xfe": "macho", b"\xca\xfe\xba\xbe": "macho_fat"}
DECOMPILE_KINDS = {"jar", "dotnet"}
JAVA_ARCHIVES = (".jar", ".war", ".ear", ".apk")
DEFAULT_GLOBS = {"jar": ["**/*.jar", "**/*.war", "**/*.ear", "**/*.apk", "*.jar", "*.war", "*.ear", "*.apk"], "dotnet": ["**/*.dll", "**/*.exe", "*.dll", "*.exe"]}


def magic_kind(path: Path) -> str | None:
    try:
        head = path.open("rb").read(4)
    except OSError:
        return None
    for sig, kind in MAGIC.items():
        if head.startswith(sig):
            return kind
    return None


def docker_sandbox(image: str, mounts: list[tuple[Path, str, bool]], args: list[str], timeout: int, mem: str = "2g") -> None:
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,exec,size=1g", "--pids-limit", "512", "--memory", mem,
        "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
    ]
    for host, ctr, ro in mounts:
        cmd += ["-v", f"{host}:{ctr}:{'ro' if ro else 'rw'}"]
    run(cmd + [image, *args], timeout=timeout)


def unblob(st: Stage, src: Path, dest: Path) -> None:
    image = TOOLS.get("unblob_image")
    if not image:
        raise StageError("unblob_image missing from tools.json")
    dest.mkdir(parents=True, exist_ok=True)
    # Java archives are decompiled whole, so unblob must not explode them into .class trees.
    skip = [a for ext in JAVA_ARCHIVES for a in ("--skip-extension", ext)] if st.cfg("artefact_kind") == "jar" else []
    docker_sandbox(
        image,
        [(src.parent, "/data/input", True), (dest, "/data/output", False)],
        [*TOOLS.get("unblob_args", []), *skip, "--extract-dir", "/data/output", f"/data/input/{src.name}"],
        timeout=st.cfg_int("unpack_timeout_min", 60, 5, 240) * 60,
    )


def unpack_one(st: Stage, src: Path, dest: Path, cap: int) -> None:
    rmtree(dest)
    dest.mkdir(parents=True)
    name = src.name.lower()
    kind = st.cfg("artefact_kind", "")
    if kind == "rpm" or name.endswith(".rpm"):
        extract_rpm(src, dest, cap)
    elif kind == "deb" or name.endswith(".deb"):
        extract_deb(src, dest, cap)
    elif kind in {"elf", "pe", "macho", "jar", "dotnet"} and (magic_kind(src) or name.endswith(JAVA_ARCHIVES)):
        shutil.copyfile(src, dest / src.name)
    elif zipfile.is_zipfile(src):
        extract_zip(src, dest, cap)
    elif tarfile.is_tarfile(src):
        extract_tar(src, dest, cap)
    else:
        unblob(st, src, dest)
    size = tree_size(dest)
    if size > cap:
        raise StageError(f"{src.name}: unpacked {size // MB}MB, over max_unpacked_mb {cap // MB}")
    log(f"unpacked {src.name} -> {dest} ({size // MB}MB)")


def package_changelog(artefact: Path, root: Path) -> dict[str, Any]:
    """Changelog text from the new package, saved so the advisory stage does not need the artefact (it may run on another host)."""
    out: dict[str, Any] = {"deb": [], "rpm": {"names": [], "texts": []}}
    for p in sorted(root.glob("usr/share/doc/*/changelog.Debian.gz"))[:5]:
        try:
            out["deb"].append(gzip.decompress(p.read_bytes()[: 8 * MB]).decode("utf-8", "replace")[: 4 * MB])
        except (OSError, EOFError):
            continue
    try:
        is_rpm = artefact.open("rb").read(4) == RPM_LEAD
    except OSError:
        is_rpm = False
    if is_rpm:
        tags = rpm_tags(artefact, {1081, 1082})
        out["rpm"] = {"names": tags.get(1081, [])[:500], "texts": [str(t)[:20000] for t in tags.get(1082, [])[:500]]}
    return out


def select(st: Stage, root: Path, version: str) -> dict[str, str]:
    globs = st.cfg_list("binary_globs", DEFAULT_GLOBS.get(st.cfg("artefact_kind", ""), []))
    extra = st.cfg("pair_normalise_regex", "")
    try:
        pair_re = re.compile(extra) if extra else None
    except re.error as e:
        raise StageError(f"bad pair_normalise_regex: {e}") from e
    picked: dict[str, str] = {}
    for rel in walk_files(root):
        p = root / rel
        if globs:
            if not glob_match(rel, globs):
                continue
        elif not magic_kind(p):
            continue
        key = normalise_rel(rel, version, pair_re)
        if key in picked:
            st.warn(f"{version}: {rel} and {picked[key]} normalise to the same key {key}")
            continue
        picked[key] = rel
    return picked


def jadx_resources() -> tuple[int, str]:
    """Threads follow the host's cores; heap is the configured floor or 45% of RAM, whichever is larger (the Pi and a c-8 worker differ)."""
    threads = int(TOOLS.get("jadx_threads") or min(os.cpu_count() or 2, 16))
    m = re.fullmatch(r"(\d+)([mg])", str(TOOLS.get("jadx_maxmem", "2g")).lower())
    floor_mb = int(m.group(1)) * (1024 if m.group(2) == "g" else 1) if m else 2048
    ram_mb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // MB
    return threads, f"{max(floor_mb, ram_mb * 45 // 100)}m"


def decompile(st: Stage, src: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    timeout = st.cfg_int("decompile_timeout_min", 45, 5, 240) * 60
    if st.cfg("artefact_kind") == "jar":
        jadx = TOOLS.get("jadx_bin")
        if not jadx:
            raise StageError("jadx_bin missing from tools.json")
        threads, heap = jadx_resources()
        env = {**os.environ, "JAVA_OPTS": f"-Xmx{heap}"}
        r = run([jadx, "--no-res", "--show-bad-code", "--no-debug-info", "-j", str(threads), "-d", str(out), str(src)],
                cwd=out, timeout=timeout, check=False, env=env)
        if r.returncode == 0:
            return
        # jadx exits non-zero for any per-class error; judge by what it wrote. Resource-only jars have nothing to decompile.
        if any(out.rglob("*.java")):
            st.warn(f"jadx rc={r.returncode} on {src.name}, partial output kept")
            return
        if zipfile.is_zipfile(src) and not any(n.endswith(".class") for n in zipfile.ZipFile(src).namelist()):
            log(f"{src.name}: no classes, nothing to decompile")
            return
        errors = [ln for ln in f"{r.stdout}\n{r.stderr}".splitlines() if "ERROR" in ln]
        raise StageError(f"jadx rc={r.returncode} on {src.name}: {' | '.join(errors[-3:])[-800:]}")
    else:
        image = TOOLS.get("ilspy_image")
        if not image:
            raise StageError("ilspy_image missing from tools.json")
        docker_sandbox(image, [(src.parent, "/in", True), (out, "/out", False)],
                       ["-p", "-o", "/out", f"/in/{src.name}"], timeout=timeout, mem="3g")


def main() -> int:
    args = base_parser(__doc__ or "").parse_args()
    st = init_stage(args)
    kind = st.cfg("artefact_kind", "")
    if kind == "source":
        fetch = read_json(st.stage_dir("fetch") / "result.json")
        if not fetch or "old" not in fetch:
            raise StageError("fetch/result.json missing; run fetch first")
        write_json(st.job_dir / "targets.json", {"mode": "git", "repo": fetch["repo"], "old": fetch["old"], "new": fetch["new"]}, indent=2)
        st.write_result({"mode": "git", "pairs": 0, "note": "source kind diffs the repo directly"})
        return 0

    artefacts = read_json(st.stage_dir("fetch") / "artefacts.json")
    if not artefacts:
        raise StageError("fetch/artefacts.json missing; run fetch first")
    cap = st.cfg_int("max_unpacked_mb", 2048, 1, 102400) * MB
    roots: dict[str, Path] = {}
    for side in ("old", "new"):
        roots[side] = st.job_dir / "unpacked" / side
        unpack_one(st, Path(artefacts[side]["path"]), roots[side], cap)
    write_json(st.job_dir / "changelog.json", package_changelog(Path(artefacts["new"]["path"]), roots["new"]), indent=1)
    sel = {side: select(st, roots[side], v) for side, v in (("old", st.old), ("new", st.new))}

    max_targets = st.cfg_int("max_targets", 25, 1, 200)
    pairs: list[dict[str, Any]] = []
    for key in sorted(set(sel["old"]) & set(sel["new"])):
        o, n = roots["old"] / sel["old"][key], roots["new"] / sel["new"][key]
        so, sn = sha256_file(o), sha256_file(n)
        pairs.append({"key": key, "old": str(o), "new": str(n), "old_sha256": so, "new_sha256": sn,
                      "identical": so == sn, "size": n.stat().st_size, "format": magic_kind(n)})
    changed = [p for p in pairs if not p["identical"]]
    if len(changed) > max_targets:
        st.warn(f"{len(changed)} changed targets, keeping the {max_targets} largest; tighten binary_globs")
        keep = {p["key"] for p in sorted(changed, key=lambda p: p["size"], reverse=True)[:max_targets]}
        for p in changed:
            if p["key"] not in keep:
                p["skipped"] = "max_targets"
    only_old = sorted(sel["old"][k] for k in set(sel["old"]) - set(sel["new"]))
    only_new = sorted(sel["new"][k] for k in set(sel["new"]) - set(sel["old"]))

    targets: dict[str, Any] = {"mode": "binary", "pairs": pairs, "only_old": only_old, "only_new": only_new}
    if kind in DECOMPILE_KINDS:
        src_root = st.job_dir / "src"
        for p in changed:
            if p.get("skipped"):
                continue
            for side in ("old", "new"):
                out = src_root / side / safe_name(p["key"].replace("/", "__"), 120)
                try:
                    decompile(st, Path(p[side]), out)
                except StageError as e:
                    st.warn(f"decompile {side} {p['key']}: {e}")
                    p["skipped"] = "decompile_failed"
        targets = {**targets, "mode": "dir", "old_dir": str(src_root / "old"), "new_dir": str(src_root / "new")}
    write_json(st.job_dir / "targets.json", targets, indent=2)
    st.write_result({
        "mode": targets["mode"], "pairs": len(pairs), "changed": len(changed),
        "identical": len(pairs) - len(changed), "only_old": len(only_old), "only_new": len(only_new),
        "only_new_sample": only_new[:10], "unpacked_mb": {s: tree_size(r) // MB for s, r in roots.items()},
    })
    return 0


if __name__ == "__main__":
    run_main(main)
