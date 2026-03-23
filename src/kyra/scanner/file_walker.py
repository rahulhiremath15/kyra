"""File walker — recursively yields scannable file paths.

Respects .gitignore and .kyraignore, skips binary files and oversized files.
Read-only: never modifies the filesystem.
"""

from __future__ import annotations

from collections.abc import Generator
from fnmatch import fnmatch
from pathlib import Path

# Files larger than this are skipped to prevent memory bloat.
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Maximum directory nesting depth.
MAX_DEPTH = 50

# Directories always skipped regardless of .gitignore.
ALWAYS_SKIP_DIRS: set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    ".eggs",
    "dist",
    "build",
    ".kyra",
}

# Extensions that are always considered binary / non-scannable.
BINARY_EXTENSIONS: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".webp",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".mkv",
    ".wav",
    ".flac",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".o",
    ".a",
    ".lib",
    ".whl",
    ".egg",
    ".pyc",
    ".pyo",
    ".class",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".sqlite",
    ".db",
}


def _load_ignore_patterns(directory: Path) -> list[str]:
    """Load gitignore-style patterns from .gitignore and .kyraignore in *directory*.

    Uses simple fnmatch-compatible patterns.  This is intentionally simpler
    than full gitignore semantics — covers the 90% case without adding a
    dependency like ``pathspec``.
    """
    patterns: list[str] = []
    for ignore_file in (".gitignore", ".kyraignore"):
        path = directory / ignore_file
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                line = line.strip()
                # Skip blanks and comments.
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    return patterns


def _is_ignored(path: Path, name: str, is_dir: bool, patterns: list[str]) -> bool:
    """Check if *name* matches any gitignore-style pattern."""
    for pat in patterns:
        # Patterns ending with '/' only match directories.
        if pat.endswith("/"):
            if is_dir and fnmatch(name, pat.rstrip("/")):
                return True
        else:
            if fnmatch(name, pat):
                return True
            # Also match against the path relative to the root for patterns
            # with slashes (e.g. "docs/internal/").
            if "/" in pat and fnmatch(str(path), f"*{pat}"):
                return True
    return False


def _is_binary(file_path: Path) -> bool:
    """Quick binary detection: check extension first, then sniff first 8 KB."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        chunk = file_path.read_bytes()[:8192]
    except OSError:
        return True  # Can't read → treat as binary (skip safely).
    # A file is binary if it contains null bytes in the first 8 KB.
    return b"\x00" in chunk


def _resolve_safe(path: Path, root: Path) -> Path | None:
    """Resolve *path* and return it only if it stays inside *root*.

    Prevents symlink-based directory traversal.  Returns ``None`` if the
    resolved path escapes the scan root.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return None
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def walk_files(
    root: str | Path,
    *,
    max_file_size: int = MAX_FILE_SIZE,
    max_depth: int = MAX_DEPTH,
    respect_gitignore: bool = True,
) -> Generator[Path, None, None]:
    """Recursively yield scannable file paths under *root*.

    Parameters
    ----------
    root:
        Top-level directory to scan.
    max_file_size:
        Skip files larger than this (bytes).
    max_depth:
        Maximum recursion depth.
    respect_gitignore:
        Whether to honour ``.gitignore`` / ``.kyraignore`` patterns.

    Yields
    ------
    Path
        Absolute paths to scannable text files.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return

    # Stack-based traversal to avoid recursion limit issues.
    # Each item: (directory_path, current_depth, accumulated_ignore_patterns)
    stack: list[tuple[Path, int, list[str]]] = [(root_path, 0, [])]

    while stack:
        current_dir, depth, parent_patterns = stack.pop()

        if depth > max_depth:
            continue

        # Merge parent patterns with patterns from this directory.
        if respect_gitignore:
            local_patterns = _load_ignore_patterns(current_dir)
            patterns = parent_patterns + local_patterns
        else:
            patterns = parent_patterns

        try:
            entries = sorted(current_dir.iterdir())
        except OSError:
            # Permission denied or similar — skip silently.
            continue

        subdirs: list[tuple[Path, int, list[str]]] = []

        for entry in entries:
            name = entry.name

            # --- Directories ---
            # Use is_symlink() + is_dir() rather than is_dir(follow_symlinks=False)
            # for Python 3.10 compatibility (follow_symlinks param added in 3.13).
            is_symlink = entry.is_symlink()
            is_directory = entry.is_dir()  # follows symlinks by default

            if is_directory:
                if name in ALWAYS_SKIP_DIRS:
                    continue
                if _is_ignored(entry, name, is_dir=True, patterns=patterns):
                    continue
                # Symlink safety check.
                if is_symlink:
                    safe = _resolve_safe(entry, root_path)
                    if safe is None:
                        continue
                subdirs.append((entry, depth + 1, patterns))
                continue

            # --- Files ---
            if is_symlink:
                safe = _resolve_safe(entry, root_path)
                if safe is None:
                    continue

            if _is_ignored(entry, name, is_dir=False, patterns=patterns):
                continue

            # Size check.
            try:
                size = entry.stat().st_size
            except OSError:
                continue
            if size > max_file_size or size == 0:
                continue

            # Binary check.
            if _is_binary(entry):
                continue

            yield entry

        # Push subdirectories onto the stack (reversed so alphabetical order
        # is preserved when popping).
        stack.extend(reversed(subdirs))
