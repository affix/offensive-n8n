"""PD fetch stage: get both versions into _cache/<product>/ (or the shared repo for source kind)."""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import time
import zipfile
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

from pdlib import (
    MB, RPM_LEAD, Stage, StageError, _safe_member, base_parser, extract_rpm, extract_tar, init_stage, log, read_json,
    render_template, rmtree, run, run_main, safe_name, sha256_file, write_json,
)

UA = "patchdiff/1.0 (+release monitoring)"
GIT_SAFE = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "core.fsmonitor=false",
]


def git(args: list[str], repo: Path | None = None, timeout: int = 1800) -> str:
    cmd = ["git", *GIT_SAFE]
    if repo is not None:
        cmd += ["--git-dir", str(repo)]
    return run(cmd + args, timeout=timeout, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).stdout


def repo_url(st: Stage) -> str:
    ref = str(st.cfg("source_ref", "")).strip()
    if re.match(r"^https://[A-Za-z0-9.-]+/", ref):
        return ref if ref.endswith(".git") else f"{ref}.git"
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", ref):
        return f"https://github.com/{ref}.git"
    raise StageError(f"source kind needs an https git URL or owner/repo in source_ref, got {ref!r}")


def tag_candidates(st: Stage, version: str) -> list[str]:
    tmpl = str(st.cfg("artefact_url_template", "")).strip()
    cands = [render_template(t.strip(), st.product, version) for t in tmpl.split("|") if t.strip()] if tmpl else []
    return cands + [c for c in (version, f"v{version}", f"{st.product}-{version}", f"release-{version}") if c not in cands]


def fetch_source(st: Stage) -> dict[str, Any]:
    repo = st.cache_dir / "repo.git"
    url = repo_url(st)
    if not (repo / "HEAD").exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        git(["init", "--bare", "--quiet", str(repo)])
        git(["remote", "add", "origin", url], repo)
    elif git(["remote", "get-url", "origin"], repo).strip() != url:
        git(["remote", "set-url", "origin", url], repo)
    git(["fetch", "--quiet", "--force", "--prune", "--no-recurse-submodules", "origin", "+refs/tags/*:refs/tags/*"], repo, timeout=3600)
    out: dict[str, Any] = {"repo": str(repo), "url": url}
    for side, version in (("old", st.old), ("new", st.new)):
        commit = tag = None
        for cand in tag_candidates(st, version):
            r = run(["git", *GIT_SAFE, "--git-dir", str(repo), "rev-parse", "--verify", "--quiet", f"refs/tags/{cand}^{{commit}}"], check=False)
            if r.returncode == 0:
                commit, tag = r.stdout.strip(), cand
                break
        if not commit:
            raise StageError(f"no tag for {version} in {url} (tried {', '.join(tag_candidates(st, version))})")
        out[side] = {"version": version, "tag": tag, "commit": commit}
        log(f"{side}: {version} -> tag {tag} ({commit[:12]})")
    count = git(["rev-list", "--count", f"{out['old']['commit']}..{out['new']['commit']}"], repo).strip()
    out["commits"] = int(count or 0)
    return out


def filename_from(resp: httpx.Response, url: str) -> str:
    cd = resp.headers.get("content-disposition", "")
    if cd:
        m = Message()
        m["content-disposition"] = cd
        name = m.get_param("filename", header="content-disposition")
        if isinstance(name, str) and name:
            return safe_name(os.path.basename(name), 120)
    return safe_name(unquote(os.path.basename(urlsplit(str(resp.url) or url).path)) or "artefact.bin", 120)


def cached(vdir: Path) -> dict[str, Any] | None:
    meta = read_json(vdir / "artefact.json")
    if not meta:
        return None
    p = vdir / meta["filename"]
    if p.is_file() and p.stat().st_size == meta.get("size") and sha256_file(p) == meta.get("sha256"):
        return {**meta, "path": str(p), "cached": True}
    log(f"cache entry {vdir} failed verification, refetching")
    return None


def record(vdir: Path, path: Path, source: str) -> dict[str, Any]:
    digest = sha256_file(path)
    meta = {"filename": path.name, "sha256": digest, "size": path.stat().st_size, "source": source,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    write_json(vdir / "artefact.json", meta, indent=2)
    (vdir / f"{path.name}.sha256").write_text(f"{digest}  {path.name}\n")
    return {**meta, "path": str(path), "cached": False}


def download(st: Stage, url: str, vdir: Path, cap: int) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise StageError(f"refusing non-https artefact URL {url}")
    part = vdir / ".download.part"
    with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, read=300), headers={"User-Agent": UA}) as client:
        with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                raise StageError(f"GET {url} -> HTTP {resp.status_code}")
            if not str(resp.url).startswith("https://"):
                raise StageError(f"{url} redirected off https to {resp.url}")
            length = int(resp.headers.get("content-length") or 0)
            if length > cap:
                raise StageError(f"{url} is {length // MB}MB, over max_artefact_mb {cap // MB}")
            name = filename_from(resp, url)
            got = 0
            with part.open("wb") as f:
                for chunk in resp.iter_bytes(MB):
                    got += len(chunk)
                    if got > cap:
                        raise StageError(f"{url} exceeded max_artefact_mb {cap // MB} while downloading")
                    f.write(chunk)
    dest = vdir / name
    os.replace(part, dest)
    dest.chmod(0o440)
    log(f"downloaded {url} -> {dest} ({got // 1024}KB)")
    return record(vdir, dest, url)


def from_inbox(st: Stage, version: str, vdir: Path, cap: int) -> dict[str, Any]:
    if not st.inbox_dir.is_dir():
        raise StageError(f"inbox {st.inbox_dir} does not exist")
    token = re.compile(rf"(?<![0-9A-Za-z.+~]){re.escape(version)}(?![0-9A-Za-z+~]|[.-]\d)")
    hits = sorted(p for p in st.inbox_dir.iterdir() if p.is_file() and not p.is_symlink() and token.search(p.name))
    if not hits:
        raise StageError(f"no file for {version} in {st.inbox_dir}")
    if len(hits) > 1:
        st.warn(f"several inbox files match {version}, using {hits[0].name}: {[h.name for h in hits]}")
    src = hits[0]
    if src.stat().st_size > cap:
        raise StageError(f"{src.name} is over max_artefact_mb {cap // MB}")
    dest = vdir / safe_name(src.name, 120)
    shutil.copyfile(src, dest)
    dest.chmod(0o440)
    return record(vdir, dest, f"inbox:{src.name}")


def from_docker(st: Stage, version: str, vdir: Path, cap: int) -> dict[str, Any]:
    image = str(st.cfg("source_ref", "")).strip()
    if not re.match(r"^[a-z0-9][a-z0-9._/-]*(:[0-9]+)?(/[a-z0-9._-]+)*$", image):
        raise StageError(f"invalid docker image {image!r}")
    ref = f"{image}:{version}"
    platform = str(st.cfg("docker_platform", "linux/arm64"))
    run(["docker", "pull", "--quiet", "--platform", platform, ref], timeout=3600)
    try:
        size = int(run(["docker", "image", "inspect", "--format", "{{.Size}}", ref]).stdout.strip() or 0)
        if size > cap:
            raise StageError(f"{ref} is {size // MB}MB, over max_artefact_mb {cap // MB}")
        cid = run(["docker", "create", "--network", "none", ref, "/nonexistent"]).stdout.strip()
        dest = vdir / f"{safe_name(image.replace('/', '_'))}-{safe_name(version)}.tar"
        try:
            run(["docker", "export", "--output", str(dest), cid], timeout=3600)
        finally:
            run(["docker", "rm", "-f", cid], check=False)
    finally:
        run(["docker", "image", "rm", ref], check=False)
    dest.chmod(0o440)
    return record(vdir, dest, f"docker:{ref}")


def fetch_artefact(st: Stage, version: str) -> dict[str, Any]:
    vdir = st.cache_dir / safe_name(version)
    vdir.mkdir(parents=True, exist_ok=True)
    hit = cached(vdir)
    if hit:
        log(f"{version}: cached {hit['path']}")
        return hit
    cap = st.cfg_int("max_artefact_mb", 512, 1, 20480) * MB
    stype = st.cfg("source_type", "")
    tmpl = str(st.cfg("artefact_url_template", "")).strip()
    if stype == "docker_tag":
        return from_docker(st, version, vdir, cap)
    if stype == "inbox" or not tmpl:
        return from_inbox(st, version, vdir, cap)
    try:
        got = download(st, first_reachable(url_candidates(tmpl, st.product, version)), vdir, cap)
    except StageError as e:
        if st.inbox_dir.is_dir():
            st.warn(f"{version}: download failed ({e}), trying inbox")
            got = from_inbox(st, version, vdir, cap)
        else:
            raise
    return unwrap(st, version, vdir, got)


RANGE_RE = re.compile(r"\{(\d+)\.\.(\d+)\}")


def url_candidates(tmpl: str, product: str, version: str) -> list[str]:
    """'|'-separated templates; {a..b} expands to a numeric range, e.g. .../HF{1..9}/... (vendor hotfix folders)."""
    out: list[str] = []
    pending = [t.strip() for t in tmpl.split("|") if t.strip()]
    while pending:
        t = pending.pop(0)
        m = RANGE_RE.search(t)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if hi - lo > 50:
                raise StageError(f"range {m.group(0)} too wide in {t!r}")
            pending[0:0] = [f"{t[:m.start()]}{n}{t[m.end():]}" for n in range(lo, hi + 1)]
            continue
        out.append(render_template(t, product, version))
    if len(out) > 60:
        raise StageError(f"artefact_url_template expands to {len(out)} URLs, max 60")
    return out


def first_reachable(urls: list[str]) -> str:
    if len(urls) == 1:
        return urls[0]
    with httpx.Client(follow_redirects=True, timeout=30, headers={"User-Agent": UA}) as client:
        for url in urls:
            if not url.startswith("https://"):
                raise StageError(f"refusing non-https artefact URL {url}")
            try:
                if client.head(url).status_code == 200:
                    log(f"found {url}")
                    return url
            except httpx.HTTPError as e:
                log(f"HEAD {url}: {e}")
    raise StageError(f"none of {len(urls)} candidate URLs answered 200 (first: {urls[0]})")


def unwrap_member(src: Path, member: str, work: Path, cap: int) -> Path:
    """Pull one member out of an RPM, zip, tar or anything 7z reads (ISO9660, UDF, cab)."""
    rmtree(work)
    work.mkdir(parents=True)
    head = src.open("rb").read(4)
    if head == RPM_LEAD:
        extract_rpm(src, work, cap)
        target = _safe_member(work, member)
    elif zipfile.is_zipfile(src):
        target = _safe_member(work, member)
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(src) as zf, zf.open(member) as fin, target.open("wb") as fout:
            shutil.copyfileobj(fin, fout, MB)
    elif tarfile.is_tarfile(src):
        extract_tar(src, work, cap)
        target = _safe_member(work, member)
    else:
        _safe_member(work, member)
        run(["7z", "e", "-y", "-bso0", "-bsp0", f"-o{work}", str(src), member], timeout=3600)
        target = work / Path(member).name
    if not target.is_file() or target.is_symlink():
        raise StageError(f"{member} not found in {src.name}")
    return target


def unwrap(st: Stage, version: str, vdir: Path, got: dict[str, Any]) -> dict[str, Any]:
    """artefact_unwrap: member paths (templated) to descend through, e.g. ISO -> RPM -> RPM. The outer files are dropped."""
    steps = [render_template(m, st.product, version) for m in st.cfg_list("artefact_unwrap", [])]
    if not steps:
        return got
    cap = st.cfg_int("max_unpacked_mb", 2048, 1, 102400) * MB
    current = Path(got["path"])
    work = vdir / ".unwrap"
    for i, member in enumerate(steps):
        inner = unwrap_member(current, member, work / str(i), cap)
        log(f"{version}: unwrapped {member} from {current.name}")
        current = inner
    dest = vdir / safe_name(current.name, 120)
    os.replace(current, dest)
    dest.chmod(0o440)
    outer = Path(got["path"])
    if outer != dest:
        outer.unlink(missing_ok=True)
        Path(f"{outer}.sha256").unlink(missing_ok=True)
    rmtree(work)
    return record(vdir, dest, f"{got['source']} -> {' -> '.join(steps)}")


def main() -> int:
    args = base_parser(__doc__ or "").parse_args()
    st = init_stage(args)
    kind = st.cfg("artefact_kind", "")
    if kind == "source":
        res = fetch_source(st)
        st.write_result({"kind": kind, **res})
        return 0
    sides = {side: fetch_artefact(st, v) for side, v in (("old", st.old), ("new", st.new))}
    if sides["old"]["sha256"] == sides["new"]["sha256"]:
        st.warn("old and new artefacts are identical")
    write_json(st.job_dir / "artefacts.json", sides, indent=2)
    st.write_result({"kind": kind, **{k: {x: v[x] for x in ("path", "sha256", "size", "cached", "source")} for k, v in sides.items()}})
    return 0


if __name__ == "__main__":
    run_main(main)
