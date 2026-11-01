"""Build a deterministic, local-only Agent Skill bundle and its checksums."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import stat
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit
from zipfile import ZIP_STORED, ZipFile, ZipInfo

_ROOT_FILES = (
    "README.md",
    "CHANGELOG.md",
    "REFERENCES.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    ".codex/guidance/readme.md",
    ".codex/guidance/actions.md",
    "pyproject.toml",
    "uv.lock",
    "plugin.json",
    "mcp.json",
    ".mcp.json",
    ".github/readme/banner.svg",
)


def build_bundle(root: Path, output: Path) -> Path:
    root = root.resolve()
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    for descriptor in ("plugin.json", ".codex-plugin/plugin.json"):
        if json.loads((root / descriptor).read_text())["version"] != version:
            raise ValueError(f"Version mismatch in {descriptor}")
    paths = [root / name for name in _ROOT_FILES]
    for directory in ("depcheck", "skills", ".codex-plugin"):
        paths.extend(path for path in (root / directory).rglob("*") if path.is_file())
    entries = []
    for path in paths:
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink() or any(
            parent.is_symlink()
            for parent in path.parents
            if parent != root and root in parent.parents
        ):
            raise ValueError(f"Bundle source must not be a symlink: {relative}")
        if not path.is_file():
            raise ValueError(f"Missing bundle source: {relative}")
        entries.append((relative.as_posix(), path.read_bytes()))
    names = {name for name, _content in entries}
    for name, content in entries:
        if not name.endswith(".md"):
            continue
        for destination in re.findall(
            r"\[[^\]]*\]\(([^)]+)\)", content.decode("utf-8")
        ):
            target = urlsplit(destination.split(" ", 1)[0].strip("<>"))
            if target.scheme or target.netloc or not target.path:
                continue
            path = posixpath.normpath(
                posixpath.join(posixpath.dirname(name), unquote(target.path))
            )
            if path not in names and not any(
                member.startswith(path.rstrip("/") + "/") for member in names
            ):
                raise ValueError(f"Missing bundle link: {name} -> {destination}")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"dependency-checker-{version}.zip"
    hashes = []
    with ZipFile(archive, "w", compression=ZIP_STORED) as bundle:
        for name, content in sorted(entries):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(info, content)
            hashes.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        info = ZipInfo("BUNDLE-MANIFEST.sha256", date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        bundle.writestr(info, "".join(hashes).encode())
    (output / "SHA256SUMS").write_text(
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".tmp/skill-bundle"))
    arguments = parser.parse_args()
    print(build_bundle(Path(__file__).resolve().parents[1], arguments.output))


if __name__ == "__main__":
    main()
