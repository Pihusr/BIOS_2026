"""Safely download and extract the supported files from a public GitHub repo."""

import ipaddress
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
from urllib.parse import quote, unquote, urljoin, urlsplit
import zipfile

import requests


_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 100 * 1024 * 1024
_MAX_FILES = 5000
_MAX_ENTRIES = 200000
_MAX_DOWNLOAD_SECONDS = 60
_MAX_COMPRESSION_RATIO = 100
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_ALLOWED_REDIRECT_HOSTS = {"github.com", "codeload.github.com"}
_SKIPPED_DIRECTORIES = {".git", "venv", ".venv", "node_modules", "site-packages"}
_ALLOWED_FILENAMES = {
    "pipfile",
    "pipfile.lock",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "poetry.lock",
}


def parse_github_url(url: str) -> tuple[str, str, str | None]:
    """Parse a strict public GitHub repository URL."""
    if not isinstance(url, str) or not url or url.startswith("-"):
        raise ValueError("Enter a public GitHub repository URL.")
    if any(character.isspace() or ord(character) < 0x20 for character in url):
        raise ValueError("GitHub repository URLs cannot contain whitespace or control characters.")
    if "?" in url or "#" in url or "\\" in url:
        raise ValueError("GitHub repository URLs cannot contain query strings or fragments.")

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError("Invalid GitHub repository URL.") from exc
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("Only https://github.com repository URLs are supported.")

    decoded_path = unquote(parsed.path)
    if ".." in decoded_path:
        raise ValueError("Repository URLs cannot contain '..' path components.")
    path = parsed.path
    if not path.startswith("/"):
        raise ValueError("Expected a GitHub repository URL.")
    parts = path[1:].split("/")
    if parts and parts[-1] == "":
        parts.pop()
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError("Expected https://github.com/<owner>/<repo>.")

    owner, repo_part = parts[0], parts[1]
    if repo_part.endswith(".git"):
        repo_part = repo_part[:-4]
    if not _valid_component(owner) or not _valid_component(repo_part):
        raise ValueError(
            "GitHub owner and repository names must use letters, numbers, '.', '_' or '-'."
        )

    branch: str | None = None
    if len(parts) > 2:
        if parts[2] != "tree" or len(parts) < 4:
            raise ValueError(
                "Only repository URLs with an optional /tree/<branch> path are supported."
            )
        branch = unquote("/".join(parts[3:]))
        if (
            not branch
            or any(not part for part in branch.split("/"))
            or ".." in branch
        ):
            raise ValueError("Invalid GitHub branch path.")
        if branch.startswith("-"):
            raise ValueError("GitHub branch names cannot start with '-'.")

    return owner, repo_part, branch


def _valid_component(value: str) -> bool:
    if not _COMPONENT_RE.fullmatch(value) or value.startswith("-"):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _redirect_target(current_url: str, location: str) -> str:
    target = urljoin(current_url, location)
    try:
        parsed = urlsplit(target)
    except ValueError as exc:
        raise ValueError("GitHub returned an invalid redirect.") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc not in _ALLOWED_REDIRECT_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        raise ValueError("GitHub redirect points to an unsupported host.")
    return target


def _download(url: str) -> tempfile.SpooledTemporaryFile[bytes]:
    downloaded = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    current_url = url
    started_at = time.monotonic()
    try:
        for redirect_count in range(6):
            response = requests.get(
                current_url,
                stream=True,
                timeout=(10, 30),
                allow_redirects=False,
            )
            try:
                status = response.status_code
                if status in _REDIRECT_STATUSES:
                    location = response.headers.get("Location")
                    if not location:
                        raise ValueError("GitHub returned a redirect without a location.")
                    if redirect_count == 5:
                        raise ValueError("GitHub returned too many redirects.")
                    current_url = _redirect_target(current_url, location)
                    continue
                if status == 404:
                    raise ValueError(
                        "Repository not found or private. Only public GitHub repos are supported."
                    )
                if status < 200 or status >= 300:
                    raise ValueError(f"GitHub returned HTTP {status}.")

                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        declared_size = int(content_length)
                    except ValueError:
                        declared_size = None
                    if declared_size is not None and declared_size > _MAX_DOWNLOAD_BYTES:
                        raise ValueError("GitHub archive exceeds the 50 MB download limit.")

                total = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if time.monotonic() - started_at > _MAX_DOWNLOAD_SECONDS:
                        raise ValueError("Download took too long.")
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise ValueError("GitHub archive exceeds the 50 MB download limit.")
                    downloaded.write(chunk)
                if time.monotonic() - started_at > _MAX_DOWNLOAD_SECONDS:
                    raise ValueError("Download took too long.")
                downloaded.seek(0)
                return downloaded
            finally:
                response.close()
        raise ValueError("GitHub returned too many redirects.")
    except requests.RequestException as exc:
        downloaded.close()
        raise ValueError(f"GitHub download failed ({type(exc).__name__}).") from exc
    except Exception:
        downloaded.close()
        raise


def fetch(url: str, dest_dir: str | os.PathLike[str]) -> str:
    """Download a repository archive and extract only supported source/manifests."""
    owner, repo, branch = parse_github_url(url)
    if branch is None:
        archive_url = f"https://github.com/{owner}/{repo}/archive/HEAD.zip"
    else:
        archive_url = (
            f"https://github.com/{owner}/{repo}/archive/refs/heads/"
            f"{quote(branch, safe='/')}.zip"
        )

    download = _download(archive_url)
    try:
        return _extract(download, Path(dest_dir), repo)
    finally:
        download.close()


def _safe_archive_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ValueError("GitHub archive contains an unsafe path.")
    if name.startswith("/") or ntpath.isabs(name) or ntpath.splitdrive(name)[0]:
        raise ValueError("GitHub archive contains an absolute or drive-letter path.")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("GitHub archive contains an unsafe path.")
    return path


def _is_whitelisted(path: PurePosixPath) -> bool:
    if any(part.lower() in _SKIPPED_DIRECTORIES for part in path.parts[:-1]):
        return False
    filename = path.name.lower()
    return (
        filename.endswith(".py")
        or (filename.startswith("requirements") and filename.endswith(".txt"))
        or filename in _ALLOWED_FILENAMES
    )


def _extract(
    archive_file: tempfile.SpooledTemporaryFile[bytes], dest_dir: Path, repo: str
) -> str:
    try:
        archive = zipfile.ZipFile(archive_file)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("GitHub did not return a valid ZIP archive.") from exc

    with archive:
        archive_entries = archive.infolist()
        if len(archive_entries) > _MAX_ENTRIES:
            raise ValueError(f"GitHub archive contains more than {_MAX_ENTRIES} entries.")

        entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        for info in archive_entries:
            path = _safe_archive_path(
                info.filename.rstrip("/") if info.is_dir() else info.filename
            )
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise ValueError("GitHub archive contains a symbolic link.")
            entries.append((info, path))

        # GitHub archives have one generated wrapper directory above the repo files.
        files = [(info, path) for info, path in entries if not info.is_dir()]
        first_parts = {path.parts[0] for _, path in files if len(path.parts) > 1}
        has_direct_files = any(len(path.parts) == 1 for _, path in files)
        strip_wrapper = len(first_parts) == 1 and not has_direct_files
        wrapper = next(iter(first_parts)) if strip_wrapper else None

        root = (dest_dir / repo).resolve()
        if root.exists():
            raise ValueError("Extraction destination already exists.")

        extraction_entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        for info, archive_path in entries:
            relative = archive_path
            if wrapper is not None:
                if relative.parts[0] != wrapper:
                    raise ValueError("GitHub archive contains inconsistent root paths.")
                relative = PurePosixPath(*relative.parts[1:])

            destination = (root / Path(*relative.parts)).resolve()
            try:
                destination.relative_to(root)
            except ValueError as exc:
                raise ValueError("GitHub archive contains a path outside the destination.") from exc

            if info.is_dir() or not relative.parts or not _is_whitelisted(relative):
                continue
            if len(extraction_entries) >= _MAX_FILES:
                raise ValueError("GitHub archive contains more than 5000 files.")
            if info.file_size and (
                info.compress_size == 0
                or info.file_size / info.compress_size > _MAX_COMPRESSION_RATIO
            ):
                raise ValueError("GitHub archive contains a suspicious compression ratio.")
            extraction_entries.append((info, relative))

        root.mkdir(parents=True)
        extracted_bytes = 0
        for info, relative in extraction_entries:
            if info.file_size > _MAX_FILE_BYTES:
                raise ValueError("GitHub archive contains a file larger than 2 MB.")
            if extracted_bytes + info.file_size > _MAX_TOTAL_BYTES:
                raise ValueError("Extracted GitHub files exceed the 100 MB limit.")

            destination = (root / Path(*relative.parts)).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            actual_file_bytes = 0
            with archive.open(info) as source, destination.open("xb") as target:
                while True:
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    actual_file_bytes += len(chunk)
                    extracted_bytes += len(chunk)
                    if actual_file_bytes > _MAX_FILE_BYTES:
                        raise ValueError("GitHub archive contains a file larger than 2 MB.")
                    if extracted_bytes > _MAX_TOTAL_BYTES:
                        raise ValueError("Extracted GitHub files exceed the 100 MB limit.")
                    target.write(chunk)
        return str(root)
