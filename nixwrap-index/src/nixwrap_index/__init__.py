"""Nix-index database package data.

This package contains the nix-index-database files for querying
Nix packages. Updated weekly from nix-community/nix-index-database.
"""

from __future__ import annotations

from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from typing import Generator


@contextmanager
def get_index(system: str) -> Generator[Path, None, None]:
    """Get path to index file for the given system.

    Args:
        system: The Nix system identifier (e.g., "x86_64-linux", "aarch64-linux")

    Yields:
        Path to the index file (extracted to temp if needed for zip installs)

    Example:
        >>> with get_index("x86_64-linux") as path:
        ...     data = path.read_bytes()
    """
    ref = files("nixwrap_index.data").joinpath(f"index-{system}")
    with as_file(ref) as path:
        yield path


def get_available_systems() -> list[str]:
    """Get list of available system architectures.

    Returns:
        List of system identifiers that have index files available.
    """
    data_files = files("nixwrap_index.data")
    systems = []
    for item in data_files.iterdir():
        if item.name.startswith("index-"):
            systems.append(item.name.removeprefix("index-"))
    return systems
