"""Acquire the curated research resources in evaluation/allowlist.json (the ONLINE step).

Run this on an approved online Linux host, never inside the offline scanning VM, and not on a
Windows host with real-time anti-malware (it quarantines the EICAR test file). It downloads
exactly the allowlisted URLs over HTTPS without following redirects, checks every file's size
and SHA-256 before keeping it, opens archives in memory and accepts only their listed members,
and writes a provenance record (URL, SHA-256, size, source, retrieval time). Nothing it fetches
is opened, executed or rendered. The verified cache is then transferred into the offline VM,
where evaluation/prepare_samples.py re-verifies every pin before use.

    python -m evaluation.acquire --out ~/fm-acquired --dry-run     # show the plan, no network
    python -m evaluation.acquire --out ~/fm-acquired               # download and verify
"""

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path(__file__).with_name("allowlist.json")
ALLOWED_HOSTS = {"secure.eicar.org", "raw.githubusercontent.com"}
MAX_DOWNLOAD_BYTES = 1024 * 1024  # every allowlisted file is far smaller
MAX_MEMBER_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 30
USER_AGENT = "FilesMagic-capstone-research-acquisition/1 (pinned allowlist; no crawling)"
SIMPLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AcquisitionError(RuntimeError):
    """A resource failed a check; nothing from it is kept."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_problems(r: dict, seen: set) -> list[str]:
    url = urlsplit(r["url"])
    problems = [
        r["id"] in seen and "duplicate id",
        url.scheme != "https" and "URL is not HTTPS",
        url.hostname not in ALLOWED_HOSTS and f"host {url.hostname!r} is not allowed",
        (url.query or url.fragment) and "URL has a query or fragment",
        r["kind"] not in ("file", "zip") and f"unknown kind {r['kind']!r}",
        not SIMPLE_NAME.match(r["save_as"]) and "save_as is not a simple file name",
        not (isinstance(r["size"], int) and 0 < r["size"] <= MAX_DOWNLOAD_BYTES) and "size missing or too large",
        r["kind"] == "file" and not SHA256.match(r.get("sha256") or "") and "a file needs a pinned sha256",
        r.get("sha256") is not None and not SHA256.match(r["sha256"]) and "sha256 is not 64 lower-case hex digits",
        r["kind"] == "zip" and not r.get("members") and "an archive needs its expected members",
    ]
    for name, member in (r.get("members") or {}).items():
        problems += [not SIMPLE_NAME.match(name) and f"member {name!r} is not a simple name",
                     not SHA256.match(member.get("sha256") or "") and f"member {name!r} needs a pinned sha256",
                     not (isinstance(member.get("size"), int) and 0 < member["size"] <= MAX_MEMBER_BYTES)
                     and f"member {name!r} size missing or too large"]
    return [p for p in problems if p]


def load_allowlist(path: Path = ALLOWLIST) -> list[dict]:
    """The resources, validated strictly: anything unexpected stops the run before any download."""
    try:
        resources = json.loads(path.read_text(encoding="utf-8"))["resources"]
        seen = set()
        for r in resources:
            if problems := entry_problems(r, seen):
                raise AcquisitionError(f"allowlist entry {r.get('id')!r}: {'; '.join(problems)}")
            seen.add(r["id"])
    except (KeyError, TypeError, AttributeError, ValueError) as e:  # a missing or mistyped field
        raise AcquisitionError(f"allowlist is malformed: {type(e).__name__}: {e}") from None
    return resources


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AcquisitionError(f"refused redirect ({code}) to {newurl!r}: only the exact allowlisted URL is fetched")


def fetch(url: str, limit: int = MAX_DOWNLOAD_BYTES) -> tuple[bytes, int]:
    """GET exactly `url`: no redirects, a timeout, and never more than `limit` bytes read."""
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            data = response.read(limit + 1)
            status = response.status
    except urllib.error.URLError as e:
        raise AcquisitionError(f"download failed: {type(e).__name__}: {getattr(e, 'reason', e)}") from None
    if len(data) > limit:
        raise AcquisitionError(f"response exceeds {limit} bytes")
    return data, status


def unsafe_member(name: str) -> bool:
    return (name.startswith(("/", "\\")) or "\\" in name or "\x00" in name or ":" in name
            or ".." in name.split("/") or "/" in name)  # allowlisted members are flat names


def extract(resource: dict, data: bytes) -> dict[str, bytes]:
    """The archive's expected members, verified; any surprise rejects the whole archive."""
    expected = resource["members"]
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile as e:
        raise AcquisitionError(f"not a readable ZIP archive: {e}") from None
    names = [i.filename for i in infos]
    if len(names) != len(set(names)):
        raise AcquisitionError("archive has duplicate member names")
    out = {}
    for info in infos:
        if unsafe_member(info.filename):
            raise AcquisitionError(f"unsafe member path {info.filename[:80]!r}")
        if info.flag_bits & 0x1:
            raise AcquisitionError("password-protected archives are refused")
        if info.filename not in expected:
            raise AcquisitionError(f"unexpected member {info.filename[:80]!r}")
        want = expected[info.filename]
        if info.file_size != want["size"] or info.file_size > MAX_MEMBER_BYTES:
            raise AcquisitionError(f"member {info.filename!r} declares {info.file_size} bytes, expected {want['size']}")
        try:
            with zf.open(info) as f:
                content = f.read(MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as e:
            raise AcquisitionError(f"member {info.filename!r} cannot be read: {type(e).__name__}") from None
        if len(content) != want["size"] or sha256(content) != want["sha256"]:
            raise AcquisitionError(f"member {info.filename!r} does not match its pinned size and SHA-256")
        out[info.filename] = content
    if missing := sorted(set(expected) - set(out)):
        raise AcquisitionError(f"archive lacks expected members: {', '.join(missing)}")
    return out


def verify(resource: dict, data: bytes) -> dict[str, bytes]:
    """Check one download against its pins. Returns verified archive members ({} for a file)."""
    if len(data) != resource["size"]:
        raise AcquisitionError(f"size {len(data)} bytes, expected {resource['size']}")
    if resource.get("sha256") and sha256(data) != resource["sha256"]:
        raise AcquisitionError(f"SHA-256 {sha256(data)} does not match the pinned {resource['sha256']}")
    return extract(resource, data) if resource["kind"] == "zip" else {}


def outside_repository(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path == REPO_ROOT or REPO_ROOT in path.parents:
        raise AcquisitionError(f"{path} is inside the repository; keep acquired files outside it")
    return path


def acquire(resources: list[dict], out: Path, fetcher=fetch, now=None) -> list[dict]:
    """Download, verify and store every resource; write provenance.json. A failed check stops
    the run and nothing from that resource is kept."""
    out = outside_repository(out)
    records = []
    for r in resources:
        retrieved = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        data, status = fetcher(r["url"])
        try:
            members = verify(r, data)
        except AcquisitionError as e:
            raise AcquisitionError(f"{r['id']}: {e}") from None
        folder = out / r["id"]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / r["save_as"]).write_bytes(data)
        for name, content in members.items():
            (folder / "extracted").mkdir(exist_ok=True)
            (folder / "extracted" / name).write_bytes(content)
        records.append({
            "id": r["id"], "source": r["source"], "page": r["page"], "url": r["url"], "http_status": status,
            "retrieved_utc": retrieved, "file": f"{r['id']}/{r['save_as']}", "size": len(data), "sha256": sha256(data),
            "sha256_pinned": bool(r.get("sha256")), "role": r["role"],
            "extracted": [{"file": f"{r['id']}/extracted/{n}", "size": len(c), "sha256": sha256(c)}
                          for n, c in members.items()],
        })
    # Merge by id: acquiring a subset later (e.g. --only eicar-com-txt) keeps earlier records.
    path = out / "provenance.json"
    earlier = json.loads(path.read_text(encoding="utf-8"))["resources"] if path.is_file() else []
    fresh = {r["id"] for r in records}
    merged = [r for r in earlier if r["id"] not in fresh] + records
    path.write_text(json.dumps({"allowlist_sha256": sha256(ALLOWLIST.read_bytes()), "resources": merged}, indent=2),
                    encoding="utf-8")
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True, help="acquisition cache, outside the repository")
    parser.add_argument("--dry-run", action="store_true", help="validate the allowlist and print the plan; no network")
    parser.add_argument("--only", nargs="+", metavar="ID", help="acquire only these allowlist ids")
    args = parser.parse_args(argv)
    try:
        resources = load_allowlist()
        if args.only:
            if unknown := set(args.only) - {r["id"] for r in resources}:
                raise AcquisitionError(f"not in the allowlist: {', '.join(sorted(unknown))}")
            resources = [r for r in resources if r["id"] in args.only]
        out = outside_repository(args.out)
        for r in resources:
            pin = r["sha256"] or f"members {', '.join(r['members'])} pinned"
            print(f"{r['id']:24s} {r['url']}\n{'':24s} {r['size']} bytes, sha256 {pin}, role {r['role']}")
        if args.dry_run:
            print(f"\nDry run: nothing downloaded. Target: {out}")
            return 0
        records = acquire(resources, out)
    except AcquisitionError as e:
        print(f"Acquisition stopped: {e}", file=sys.stderr)
        return 2
    print(f"\nVerified {len(records)} resources into {out}; see {out / 'provenance.json'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
