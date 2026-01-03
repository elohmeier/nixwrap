"""Nix-index database querying.

This module provides functionality to parse and query the nix-index-database
to find packages and their binaries.
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass, field
from pathlib import Path

# Try Python 3.14+ stdlib first, fall back to zstandard package
try:
    import compression.zstd as zstd

    def decompress_zstd_stream(f) -> bytes:
        """Decompress zstd stream from file object."""
        compressed_data = f.read()
        return zstd.decompress(compressed_data)
except ImportError:
    try:
        import zstandard

        def decompress_zstd_stream(f) -> bytes:
            """Decompress zstd stream from file object."""
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(f)
            chunks = []
            while True:
                chunk = reader.read(4 * 1024 * 1024)  # 4MB chunks
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
    except ImportError:
        def decompress_zstd_stream(f) -> bytes:
            raise ImportError("Python 3.14+ or zstandard package required")


# Pre-compiled regex patterns for speed
_PKG_PATTERN = re.compile(
    rb'\{"store_dir":"/nix/store","hash":"([a-z0-9]+)","name":"([^"]+)",'
    rb'"origin":\{"attr":"([^"]+)","output":"([^"]+)","toplevel":(true|false),'
    rb'"system":"([^"]+)"\}\}'
)

# Pattern for relative binary entries that appear before package metadata
# Format: bin\n followed by entries like 6572488x\x00\x03/rg
# The 'x' indicates executable, the byte after \x00 is string length metadata
_REL_BIN_PATTERN = re.compile(
    rb'bin\n(?:.*?(\d+)x\x00./(\.?[a-zA-Z0-9][a-zA-Z0-9._-]*)\n?)*',
    re.DOTALL
)

# Pattern for individual binary entries within a bin section
# Format: <SIZE>x\x00<META>/? <BINARY_NAME>
# Some entries have / prefix, some don't (e.g., .bat-wrapped)
_BIN_ENTRY_PATTERN = re.compile(
    rb'\d+x\x00./?(\.?[a-zA-Z0-9][a-zA-Z0-9._-]*)'
)


@dataclass
class BinaryInfo:
    """Information about a binary provided by a package."""

    path: str  # e.g., "bin/rg" or "bin/.rg-wrapped"
    command: str  # e.g., "rg"
    is_wrapper: bool  # True if this is a Nix wrapper script


@dataclass
class PackageInfo:
    """Information about a Nix package."""

    attr: str  # e.g., "ripgrep"
    name: str  # e.g., "ripgrep-14.1.0"
    store_hash: str  # 32-char hash
    store_path: str  # e.g., "/nix/store/abc123-ripgrep-14.1.0"
    system: str  # e.g., "x86_64-linux"
    binaries: list[BinaryInfo] = field(default_factory=list)

    @property
    def version(self) -> str:
        """Extract version from package name."""
        match = re.search(r"-(\d+\.\d+[.\d]*)", self.name)
        return match.group(1) if match else "0.0.0"


def detect_system() -> str:
    """Detect the current Nix system identifier."""
    machine = platform.machine()
    if machine == "x86_64":
        return "x86_64-linux"
    elif machine == "aarch64":
        return "aarch64-linux"
    else:
        raise ValueError(f"Unsupported architecture: {machine}")


def _parse_index(path: Path) -> dict[str, PackageInfo]:
    """Parse a nix-index database file.

    The nix-index format stores file listings followed by package metadata.
    For each package, binaries appear in the format:
        bin\n<SIZE>x\x00<LEN>/<BINARY_NAME>
    followed by the package JSON metadata.

    Args:
        path: Path to the index file

    Returns:
        Dict mapping package attr to PackageInfo
    """
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"NIXI":
            raise ValueError(f"Invalid nix-index magic: {magic!r}")
        f.read(8)  # version

        # Decompress using zstd streaming
        data = decompress_zstd_stream(f)

    packages: dict[str, PackageInfo] = {}

    # Find all package metadata entries and look backwards for binaries
    for match in _PKG_PATTERN.finditer(data):
        hash_ = match.group(1).decode()
        name = match.group(2).decode()
        attr = match.group(3).decode()
        output = match.group(4).decode()
        toplevel = match.group(5) == b"true"
        system = match.group(6).decode()

        # Only include toplevel packages with "out" output
        if not toplevel or output != "out":
            continue

        # Look backwards from the package metadata to find bin entries
        # The format before package metadata includes file listings
        # We look for "bin\n" followed by executable entries
        search_start = max(0, match.start() - 2000)  # Look back up to 2KB
        context = data[search_start:match.start()]

        binaries: list[BinaryInfo] = []

        # Find the last "bin\n" section before the package metadata
        bin_pos = context.rfind(b"bin\n")
        if bin_pos != -1:
            # Extract the bin section (from bin\n to end of context)
            bin_section = context[bin_pos:]

            # Find all executable entries (marked with 'x')
            for bin_match in _BIN_ENTRY_PATTERN.finditer(bin_section):
                bin_name = bin_match.group(1).decode()

                is_wrapper = bin_name.startswith(".")
                if is_wrapper:
                    cmd_name = bin_name[1:].replace("-wrapped", "")
                else:
                    cmd_name = bin_name

                binaries.append(
                    BinaryInfo(
                        path=f"bin/{bin_name}",
                        command=cmd_name,
                        is_wrapper=is_wrapper,
                    )
                )

        # Only add packages that have binaries
        if binaries:
            pkg = PackageInfo(
                attr=attr,
                name=name,
                store_hash=hash_,
                store_path=f"/nix/store/{hash_}-{name}",
                system=system,
                binaries=binaries,
            )
            packages[attr] = pkg

    return packages


class NixIndex:
    """Query nix-index-database for package information."""

    def __init__(self, system: str | None = None, index_path: Path | None = None):
        """Initialize the index.

        Args:
            system: Nix system identifier. If None, auto-detected.
            index_path: Direct path to index file. If None, uses nixwrap-index package.
        """
        self.system = system or detect_system()
        self._index_path = index_path
        self._packages: dict[str, PackageInfo] = {}
        self._loaded = False

    def load(self) -> None:
        """Parse the nix-index database."""
        if self._loaded:
            return

        if self._index_path:
            # Direct path provided
            self._packages = _parse_index(self._index_path)
        else:
            # Use nixwrap-index package
            from nixwrap_index import get_index

            with get_index(self.system) as path:
                self._packages = _parse_index(path)

        self._loaded = True

    def find_package(self, attr: str) -> PackageInfo | None:
        """Find package by attribute name.

        Args:
            attr: The nixpkgs attribute name (e.g., "ripgrep")

        Returns:
            PackageInfo if found, None otherwise
        """
        self.load()
        return self._packages.get(attr)

    def find_by_command(self, command: str) -> list[PackageInfo]:
        """Find packages providing a command.

        Args:
            command: The command name (e.g., "rg")

        Returns:
            List of packages that provide this command
        """
        self.load()
        return [
            p
            for p in self._packages.values()
            if any(b.command == command for b in p.binaries)
        ]

    def list_packages(self) -> list[str]:
        """List all available package attrs.

        Returns:
            Sorted list of package attribute names
        """
        self.load()
        return sorted(self._packages.keys())

    def __len__(self) -> int:
        """Return number of packages in index."""
        self.load()
        return len(self._packages)


def select_primary_binary(binaries: list[BinaryInfo], pkg_name: str) -> BinaryInfo:
    """Select the primary binary for a package.

    Priority:
    1. Wrapper matching package name
    2. Non-wrapper matching package name
    3. Any wrapper
    4. Shortest command name

    Args:
        binaries: List of binaries from the package
        pkg_name: The package name (e.g., "ripgrep-14.1.0")

    Returns:
        The selected primary binary
    """
    if not binaries:
        raise ValueError("No binaries to select from")

    # Extract base name without version
    base_name = re.sub(r"-\d+.*$", "", pkg_name)

    # Prefer wrapper that matches package name
    for b in binaries:
        if b.is_wrapper and b.command == base_name:
            return b

    # Non-wrapper matching package name
    for b in binaries:
        if not b.is_wrapper and b.command == base_name:
            return b

    # Any wrapper
    for b in binaries:
        if b.is_wrapper:
            return b

    # Shortest name (likely main command)
    return min(binaries, key=lambda x: len(x.command))
