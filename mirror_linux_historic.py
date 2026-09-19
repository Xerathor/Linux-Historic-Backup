#!/usr/bin/env python3
"""
Mirror the historical Linux kernel archive from kernel.org.

Default source:
    https://www.kernel.org/pub/linux/kernel/Historic/

The directory structure is preserved exactly under --dest.

Examples:
    python mirror_linux_historic.py
    python mirror_linux_historic.py --dest /backups/linux-historic
    python mirror_linux_historic.py --dest ./linux-historic --workers 8
    python mirror_linux_historic.py --dest ./linux-historic --check
    python mirror_linux_historic.py --dest ./linux-historic --verify-sha256

Python 3.9+; standard library only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html.parser
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_URL = "https://www.kernel.org/pub/linux/kernel/Historic/"
USER_AGENT = "linux-historic-mirror/1.1 (+archival backup)"
RETRYABLE = (urllib.error.URLError, TimeoutError, ConnectionError, OSError)


class IndexParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


def normalize_base(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def get_url(url: str, timeout: int, ctx: ssl.SSLContext):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/octet-stream,*/*",
        },
    )
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def fetch_text(url: str, timeout: int, ctx: ssl.SSLContext) -> str:
    with get_url(url, timeout, ctx) as r:
        charset = r.headers.get_content_charset() or "utf-8"
        return r.read().decode(charset, errors="replace")


def list_index(url: str, timeout: int, ctx: ssl.SSLContext) -> tuple[list[str], list[str]]:
    """
    Return (directories, files) from a kernel.org-style Apache index.
    Only relative links inside the current directory are accepted.
    """
    text = fetch_text(url, timeout, ctx)
    parser = IndexParser()
    parser.feed(text)

    dirs: list[str] = []
    files: list[str] = []

    for href in parser.links:
        href = urllib.parse.unquote(href)

        if href in ("../", "./", ""):
            continue

        # Ignore absolute/external links and query/fragment links.
        parsed = urllib.parse.urlsplit(href)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            continue

        # Prevent escaping the archive root.
        if href.startswith("/"):
            continue

        if href.endswith("/"):
            name = href[:-1]
            if name and "/" not in name:
                dirs.append(name)
        else:
            name = href
            if name and "/" not in name:
                files.append(name)

    return sorted(set(dirs)), sorted(set(files))


def walk_archive(
    base_url: str,
    timeout: int,
    ctx: ssl.SSLContext,
) -> list[tuple[str, str]]:
    """
    Returns [(relative_posix_path, url), ...] for every file under base_url.
    """
    todo = [("", normalize_base(base_url))]
    files: list[tuple[str, str]] = []

    while todo:
        rel_dir, current_url = todo.pop()
        print(f"[INDEX] {current_url}")

        dirs, names = list_index(current_url, timeout, ctx)

        for name in names:
            rel = f"{rel_dir}{name}"
            files.append((rel, urllib.parse.urljoin(current_url, name)))

        for dirname in reversed(dirs):
            child_rel = f"{rel_dir}{dirname}/"
            child_url = urllib.parse.urljoin(current_url, dirname + "/")
            todo.append((child_rel, child_url))

    return files


def safe_output_path(root: Path, rel_posix: str) -> Path:
    """
    Convert an archive-relative POSIX path to a local path safely.

    Uses os.path.commonpath() instead of Path.relative_to() because the latter
    can be surprisingly strict on Windows (drive/case/path normalization).
    """
    decoded = urllib.parse.unquote(rel_posix).replace("\\\\", "/")
    rel = PurePosixPath(decoded)

    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"Unsafe archive path: {rel_posix!r}")

    root_abs = os.path.abspath(os.path.normpath(os.fspath(root)))
    candidate_abs = os.path.abspath(
        os.path.normpath(os.path.join(root_abs, *rel.parts))
    )

    # Windows paths can differ only by case; commonpath() is compared
    # case-insensitively on Windows.
    root_cmp = root_abs.casefold() if os.name == "nt" else root_abs
    candidate_cmp = candidate_abs.casefold() if os.name == "nt" else candidate_abs

    try:
        common = os.path.commonpath([root_cmp, candidate_cmp])
    except ValueError as exc:
        # Usually means different Windows drives.
        raise ValueError(f"Path escapes destination: {rel_posix!r}") from exc

    if common != root_cmp:
        raise ValueError(f"Path escapes destination: {rel_posix!r}")

    return Path(candidate_abs)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def download_one(
    rel_path: str,
    url: str,
    root: Path,
    timeout: int,
    retries: int,
    ctx: ssl.SSLContext,
    force: bool = False,
) -> tuple[str, int, str]:
    dest = safe_output_path(root, rel_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")

    if dest.exists() and not force and dest.is_file():
        return rel_path, dest.stat().st_size, "exists"

    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            start = part.stat().st_size if part.exists() else 0

            headers = {
                "User-Agent": USER_AGENT,
                "Accept": "application/octet-stream,*/*",
            }
            if start:
                headers["Range"] = f"bytes={start}-"

            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                status = getattr(r, "status", None)
                # Some servers may ignore Range and send the file from byte 0.
                if start and status != 206:
                    start = 0
                    part.unlink(missing_ok=True)
                    headers.pop("Range", None)
                    req = urllib.request.Request(url, headers=headers)
                    r.close()
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as rr:
                        with part.open("wb") as f:
                            while True:
                                chunk = rr.read(1024 * 1024)
                                if not chunk:
                                    break
                                f.write(chunk)
                else:
                    mode = "ab" if start else "wb"
                    with part.open(mode) as f:
                        while True:
                            chunk = r.read(1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)

            os.replace(part, dest)
            return rel_path, dest.stat().st_size, "downloaded"

        except RETRYABLE as exc:
            last_exc = exc
            wait = min(2 ** (attempt - 1), 30)
            print(
                f"[RETRY {attempt}/{retries}] {rel_path}: {exc}; "
                f"waiting {wait}s",
                file=sys.stderr,
            )
            time.sleep(wait)

    raise RuntimeError(f"Failed to download {rel_path}: {last_exc}")


def parse_sha256sums(path: Path) -> dict[str, str]:
    """
    Parse common sha256sums.asc forms:
        HASH  filename
        HASH *filename
    Ignore OpenPGP armor, comments, malformed lines, and unrelated hashes.
    """
    result: dict[str, str] = {}
    if not path.exists():
        return result

    pattern = re.compile(r"^([0-9a-fA-F]{64})\s+[* ]?(.*)$")

    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        m = pattern.match(line)
        if not m:
            continue
        digest = m.group(1).lower()
        name = m.group(2).strip()
        if name:
            result[name] = digest

    return result


def verify_sha256_sidecars(root: Path) -> tuple[int, int]:
    checked = 0
    failed = 0

    for sums_path in root.rglob("sha256sums.asc"):
        sums = parse_sha256sums(sums_path)
        base = sums_path.parent

        for rel_name, expected in sums.items():
            # The checksum files in the kernel archive normally contain only
            # filenames relative to the directory containing sha256sums.asc.
            candidate = (base / rel_name).resolve()

            try:
                candidate.relative_to(root.resolve())
            except ValueError:
                print(f"[SHA256] SKIP unsafe filename: {rel_name}")
                continue

            if not candidate.is_file():
                print(f"[SHA256] MISSING {candidate}")
                failed += 1
                continue

            actual = sha256_file(candidate)
            checked += 1

            if actual == expected:
                print(f"[SHA256] OK      {candidate.relative_to(root)}")
            else:
                failed += 1
                print(
                    f"[SHA256] FAILED  {candidate.relative_to(root)}\n"
                    f"          expected: {expected}\n"
                    f"          actual:   {actual}"
                )

    return checked, failed


def write_manifest(root: Path, manifest_name: str = "MIRROR-MANIFEST.sha256") -> Path:
    files = sorted(
        p for p in root.rglob("*")
        if p.is_file()
        and p.name != manifest_name
        and not p.name.endswith(".part")
    )

    out = root / manifest_name
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for path in files:
            rel = path.relative_to(root).as_posix()
            f.write(f"{sha256_file(path)}  {rel}\n")

    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Mirror kernel.org Historical Linux kernel archive."
    )
    ap.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Archive root (default: {DEFAULT_URL})",
    )
    ap.add_argument(
        "--dest",
        default="./linux-historic",
        help="Local destination directory (default: ./linux-historic)",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=6,
        help="Parallel downloads (default: 6)",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Retries per file (default: 5)",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout in seconds (default: 60)",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Re-download files that already exist.",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Do not download; report files missing locally relative to the archive.",
    )
    ap.add_argument(
        "--verify-sha256",
        action="store_true",
        help="Verify files against every downloaded sha256sums.asc.",
    )
    ap.add_argument(
        "--no-manifest",
        action="store_true",
        help="Do not generate a local MIRROR-MANIFEST.sha256.",
    )

    args = ap.parse_args()

    if args.workers < 1:
        ap.error("--workers must be >= 1")
    if args.retries < 1:
        ap.error("--retries must be >= 1")

    root = Path(args.dest).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    ctx = ssl.create_default_context()
    base = normalize_base(args.url)

    print(f"Archive: {base}")
    print(f"Destination: {root}")

    try:
        archive_files = walk_archive(base, args.timeout, ctx)
    except Exception as exc:
        print(f"[FATAL] Cannot enumerate archive: {exc}", file=sys.stderr)
        return 2

    archive_files.sort()

    print(f"[INFO] Files found in archive: {len(archive_files)}")

    missing = 0
    for rel, _ in archive_files:
        local = safe_output_path(root, rel)
        if not local.is_file():
            missing += 1

    if args.check:
        print(f"[CHECK] Missing locally: {missing}")
        return 0 if missing == 0 else 1

    failures: list[str] = []
    downloaded = 0
    skipped = 0

    def worker(item):
        return download_one(
            item[0],
            item[1],
            root,
            args.timeout,
            args.retries,
            ctx,
            force=args.force,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(worker, item): item for item in archive_files}

        for fut in concurrent.futures.as_completed(futures):
            item = futures[fut]
            rel = item[0]
            try:
                rel_path, size, status = fut.result()
                if status == "downloaded":
                    downloaded += 1
                    print(f"[DONE]   {rel_path} ({size:,} bytes)")
                else:
                    skipped += 1
                    print(f"[SKIP]   {rel_path} (already exists)")
            except Exception as exc:
                failures.append(rel)
                print(f"[FAILED] {rel}: {exc}", file=sys.stderr)

    print()
    print(f"Archive files: {len(archive_files)}")
    print(f"Downloaded:    {downloaded}")
    print(f"Existing:      {skipped}")
    print(f"Failed:        {len(failures)}")

    if failures:
        print("\nFailed files:")
        for rel in sorted(failures):
            print(f"  {rel}")

    if not args.no_manifest:
        manifest = write_manifest(root)
        print(f"\nManifest: {manifest}")

    if args.verify_sha256:
        checked, failed_sha = verify_sha256_sidecars(root)
        print(f"\nSHA-256 checked: {checked}")
        print(f"SHA-256 failures: {failed_sha}")
        if failed_sha:
            return 3

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
