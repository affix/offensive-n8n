"""PD advisory stage: pull advisories for the new version and mark candidates they plausibly cover.

advisory_feed accepts one or more entries separated by '|' or newlines:
  https://...            RSS/Atom feed (vendor PSIRT)
  ghsa:<owner>/<repo>    GitHub security advisories for a repo
  ghsa-eco:<eco>:<pkg>   GitHub advisories for a package (npm, pip, maven, nuget, go, rubygems, composer, rust)
  cpe:2.3:...            NVD CVEs for a CPE (virtual match string, version wildcarded)
GITHUB_TOKEN and NVD_API_KEY are optional and only read from the environment.
"""

from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from pdlib import Stage, StageError, base_parser, init_stage, log, read_json, run_main, write_json

UA = "patchdiff/1.0 (+advisory matching)"
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b", re.I)
STOP = {"the", "and", "for", "with", "from", "that", "this", "version", "versions", "before", "after", "allows", "could",
        "attacker", "remote", "via", "function", "file", "code", "user", "data", "value", "error", "issue", "main", "init", "src", "lib"}


def parse_version(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        m = re.search(r"\d+(\.\d+)+", v)
        try:
            return Version(m.group(0)) if m else None
        except InvalidVersion:
            return None


def in_range(old: str, new: str, text: str) -> bool:
    """Advisory relevant if it names the new version, or a fixed-in version in (old, new]."""
    dotted = new.replace("_", ".")
    if new in text or (dotted != new and dotted in text):
        return True
    vo, vn = parse_version(old.replace("_", ".")), parse_version(dotted)
    if not vo or not vn:
        return False
    for m in re.finditer(r"\b\d+(?:\.\d+){1,3}\b", text):
        v = parse_version(m.group(0))
        if v and vo < v <= vn:
            return True
    return False


def client() -> httpx.Client:
    return httpx.Client(follow_redirects=True, timeout=httpx.Timeout(30, read=60), headers={"User-Agent": UA})


def feed_rss(c: httpx.Client, url: str) -> list[dict[str, str]]:
    r = c.get(url)
    r.raise_for_status()
    if len(r.content) > 20 * 1024 * 1024:
        raise StageError(f"feed {url} too large")
    root = ET.fromstring(r.content)  # stdlib parser: no external entity resolution
    out = []
    for item in root.iter():
        tag = item.tag.rsplit("}", 1)[-1]
        if tag not in {"item", "entry"}:
            continue
        def get(name: str, node: ET.Element = item) -> str:
            return " ".join((e.text or "") for e in node.iter() if e.tag.rsplit("}", 1)[-1] == name)

        link = get("link") or next((e.get("href", "") for e in item.iter() if e.tag.rsplit("}", 1)[-1] == "link"), "")
        out.append({"id": (CVE_RE.search(get("title") + get("description") + get("summary")) or [None])[0] or link,
                    "title": get("title").strip()[:300],
                    "text": re.sub(r"<[^>]+>", " ", get("description") + " " + get("summary") + " " + get("content"))[:6000],
                    "url": link.strip(), "source": "rss"})
    return out


def gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    return h


def ghsa_repo(c: httpx.Client, repo: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100&state=published"
    r = c.get(url, headers=gh_headers())
    if r.status_code == 404:
        return out
    r.raise_for_status()
    for a in r.json():
        out.append(_ghsa_row(a))
    return out


def ghsa_eco(c: httpx.Client, eco: str, pkg: str) -> list[dict[str, str]]:
    r = c.get("https://api.github.com/advisories", params={"ecosystem": eco, "affects": pkg, "per_page": 100}, headers=gh_headers())
    r.raise_for_status()
    return [_ghsa_row(a) for a in r.json()]


def _ghsa_row(a: dict[str, Any]) -> dict[str, str]:
    vulns = a.get("vulnerabilities") or []
    ranges = "; ".join(f"{v.get('vulnerable_version_range')} fixed {v.get('patched_versions') or v.get('first_patched_version')}" for v in vulns)
    return {"id": a.get("cve_id") or a.get("ghsa_id"), "title": (a.get("summary") or "")[:300],
            "text": f"{a.get('description') or ''}\nAffected: {ranges}\nCWE: {', '.join(c.get('cwe_id', '') for c in a.get('cwes') or [])}"[:6000],
            "url": a.get("html_url") or "", "source": "ghsa"}


def nvd_cpe(c: httpx.Client, cpe: str) -> list[dict[str, str]]:
    parts = cpe.split(":")
    if len(parts) < 6:
        raise StageError(f"bad cpe {cpe}")
    match = ":".join(parts[:5] + ["*"] * (13 - 5))
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    out = []
    start = 0
    while start < 2000:
        r = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                  params={"virtualMatchString": match, "startIndex": start, "resultsPerPage": 200}, headers=headers)
        if r.status_code in (403, 429):
            time.sleep(8)
            r = c.get(r.request.url, headers=headers)
        r.raise_for_status()
        data = r.json()
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            cfg = str(cve.get("configurations", ""))[:3000]
            out.append({"id": cve["id"], "title": desc[:300], "text": f"{desc}\n{cfg}"[:6000],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}", "source": "nvd"})
        start += data.get("resultsPerPage", 200)
        if start >= data.get("totalResults", 0):
            break
        time.sleep(6 if not headers else 1)
    return out


def debian_changelog(st: Stage) -> list[dict[str, str]]:
    """CVE entries from the new .deb's changelog.Debian.gz, newer than the old version (distro backports keep upstream versions)."""
    out: list[dict[str, str]] = []
    for text in changelogs(st)["deb"]:
        log_path = st.stage_dir("unpack") / "changelog.json"
        for entry in re.split(r"\n(?=\S+ \([^)]+\) )", text):
            head = re.match(r"(\S+) \(([^)]+)\)", entry)
            if not head:
                continue
            if head.group(2) == st.old:
                break
            ids = sorted({m.upper() for m in CVE_RE.findall(entry)})
            for cid in ids or [f"{head.group(1)}-{head.group(2)}"]:
                bullets = [re.sub(r"\s+", " ", b).strip() for b in re.split(r"\n\s*[*-] ", entry)]
                lines = [b for b in bullets if cid in b.upper()] or [entry[:600]]
                out.append({"id": cid, "title": f"{head.group(1)} {head.group(2)} changelog: {lines[0][:200]}",
                            "text": f"{head.group(2)}\n" + "\n".join(lines)[:3000], "url": str(log_path), "source": "debian-changelog"})
    return out


def changelogs(st: Stage) -> dict[str, Any]:
    return read_json(st.stage_dir("unpack") / "changelog.json") or {"deb": [], "rpm": {"names": [], "texts": []}}


def rpm_changelog(st: Stage) -> list[dict[str, str]]:
    """CVE entries from the new RPM's %changelog header, newer than the old version (vendor rebuilds keep upstream versions)."""
    rpm = changelogs(st)["rpm"]
    names, texts = rpm.get("names", []), rpm.get("texts", [])
    path = st.stage_dir("unpack") / "changelog.json"
    old = st.old.split(":", 1)[-1]
    out: list[dict[str, str]] = []
    for name, text in zip(names, texts, strict=False):
        evr = str(name).rsplit(" - ", 1)[-1].strip().split(":", 1)[-1] if " - " in str(name) else ""
        if evr and (evr == old or old.startswith(f"{evr}.") or evr.startswith(f"{old}-")):
            break
        entry = str(text)
        bullets = [re.sub(r"\s+", " ", b).strip() for b in re.split(r"\n(?=- )", entry)]
        for cid in sorted({m.upper() for m in CVE_RE.findall(entry)}) or [f"{st.product}-{evr or 'unversioned'}"]:
            lines = [b for b in bullets if cid in b.upper()] or [entry[:600]]
            out.append({"id": cid, "title": f"rpm {evr} changelog: {lines[0][:200]}",
                        "text": f"{evr}\n" + "\n".join(lines)[:3000], "url": str(path), "source": "rpm-changelog"})
    return out


def tokens_for(cand: dict[str, Any]) -> set[str]:
    toks: set[str] = set()
    f = cand.get("file") or ""
    p = PurePosixPath(f.replace("{v}", ""))
    toks.update({p.name.lower(), p.stem.lower()})
    toks.update(part.lower() for part in p.parts[-3:-1] if len(part) > 3)
    fn = cand.get("function") or ""
    for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", fn):
        toks.add(t.lower())
    return {t for t in toks if len(t) > 3 and t not in STOP}


def main() -> int:
    p = base_parser(__doc__ or "")
    p.add_argument("--candidates", default="", help="candidates.json path (default <run>/diff/candidates.json)")
    args = p.parse_args()
    st = init_stage(args)
    cand_path = Path(args.candidates) if args.candidates else st.stage_dir("diff") / "candidates.json"
    cands = read_json(cand_path)
    if cands is None:
        raise StageError(f"missing {cand_path}")
    feeds = [f.strip() for f in re.split(r"[|\n]", str(st.cfg("advisory_feed", ""))) if f.strip()]
    advisories: list[dict[str, str]] = []
    with client() as c:
        for feed in feeds:
            try:
                if feed.startswith("https://"):
                    got = feed_rss(c, feed)
                elif feed.startswith("ghsa:"):
                    got = ghsa_repo(c, feed[5:])
                elif feed.startswith("ghsa-eco:"):
                    _, eco, pkg = feed.split(":", 2)
                    got = ghsa_eco(c, eco, pkg)
                elif feed.startswith("cpe:2.3:"):
                    got = nvd_cpe(c, feed)
                else:
                    st.warn(f"unknown advisory_feed entry {feed!r}")
                    continue
            except (httpx.HTTPError, ET.ParseError, StageError) as e:
                st.warn(f"advisory feed {feed}: {e}")
                continue
            log(f"{feed}: {len(got)} advisories")
            advisories.extend(got)
    for name, fn in (("debian", debian_changelog), ("rpm", rpm_changelog)):
        got = fn(st)
        if got:
            log(f"{name} changelog: {len(got)} entries newer than {st.old}")
            advisories.extend(got)
    relevant = [a for a in advisories if a.get("source") in {"debian-changelog", "rpm-changelog"} or in_range(st.old, st.new, f"{a['title']}\n{a['text']}")]
    seen: set[str] = set()
    relevant = [a for a in relevant if not (a["id"] in seen or seen.add(a["id"]))]
    log(f"{len(relevant)} advisories relevant to {st.old}..{st.new}")

    for cand in cands:
        toks = tokens_for(cand)
        commit_text = " ".join(f"{x.get('subject', '')} {x.get('body', '')}" for x in cand.get("commits", []))
        named = sorted({m.upper() for m in CVE_RE.findall(commit_text)})
        best, best_hits = None, []
        for a in relevant:
            blob = f"{a['title']} {a['text']}".lower()
            hits = sorted(t for t in toks if re.search(rf"(?<![a-z0-9_]){re.escape(t)}(?![a-z0-9_])", blob))
            if a["id"] and a["id"].upper() in named:
                hits.append("commit_reference")
            if len(hits) > len(best_hits):
                best, best_hits = a, hits
        cand["advisory_match"] = best["id"] if best and best_hits else (named[0] if named else None)
        cand["advisory_hits"] = best_hits
        cand["advisory_text"] = (f"{best['id']}: {best['title']}\n{best['text'][:1500]}" if best and best_hits else "")
    write_json(st.job_dir / "advisories.json", relevant, indent=1)
    write_json(st.job_dir / "candidates.json", cands, indent=1)
    st.write_result({
        "feeds": len(feeds), "advisories_total": len(advisories), "advisories_relevant": len(relevant),
        "advisory_ids": [a["id"] for a in relevant][:30], "candidates": len(cands),
        "matched": sum(1 for c in cands if c.get("advisory_match")),
        "candidates_path": str(st.job_dir / "candidates.json"),
    })
    return 0


if __name__ == "__main__":
    run_main(main)
