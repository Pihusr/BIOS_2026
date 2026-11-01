from __future__ import annotations

from pathlib import Path, PurePosixPath
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "fixtures" / "ground_truth_repo"
ARCHIVE = Path.home() / "Downloads" / "hawkeye-ground-truth-demo.zip"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
EXCLUDED_NAMES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    ".ds_store",
}


def main() -> int:
    """Package the ground-truth fixture for the Streamlit ZIP uploader."""
    if not SOURCE.is_dir():
        raise FileNotFoundError(f"Ground-truth repository not found: {SOURCE}")

    ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    included_files: list[Path] = []
    with zipfile.ZipFile(
        ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in SOURCE.rglob("*"):
            relative_path = path.relative_to(SOURCE)
            if any(part.lower() in EXCLUDED_NAMES for part in relative_path.parts):
                continue
            if not path.is_file() or path.suffix.lower() == ".pyc":
                continue

            archive_path = PurePosixPath(SOURCE.name, *relative_path.parts)
            archive.write(path, archive_path.as_posix())
            included_files.append(path)

    size = ARCHIVE.stat().st_size
    print(f"Created: {ARCHIVE}")
    print(f"Size: {size:,} bytes ({size / (1024 * 1024):.2f} MiB)")
    if size <= MAX_UPLOAD_BYTES:
        return 0

    print("ERROR: archive exceeds the 10 MiB upload limit. Largest included files:")
    for path in sorted(included_files, key=lambda item: item.stat().st_size, reverse=True)[:10]:
        print(f"  {path.stat().st_size:>10,} bytes  {path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
