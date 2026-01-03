"""CLI for running Nix packages directly.

Usage:
    nixwrap <package> [args...]
    nixwrap run <package> [args...]
    nixwrap info <package>

Examples:
    uv run nixwrap ripgrep --version
    uv run nixwrap run fd --help
    uv run nixwrap info jq
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .index import NixIndex, detect_system, select_primary_binary


def _get_index() -> NixIndex:
    """Get a NixIndex, trying local paths first for development."""
    # Try common local paths for development
    # Path structure: src/nixwrap/cli.py -> go up 3 levels to repo root
    repo_root = Path(__file__).parent.parent.parent
    local_paths = [
        repo_root / "nixwrap-index" / "src" / "nixwrap_index" / "data",
        Path.home() / ".cache" / "nixwrap" / "index",
    ]

    system = detect_system()

    for base in local_paths:
        index_path = base / f"index-{system}"
        if index_path.exists():
            return NixIndex(system=system, index_path=index_path)

    # Fall back to nixwrap-index package
    return NixIndex(system=system)


def get_cache_dir() -> Path:
    """Get the nixwrap cache directory.

    Uses XDG_CACHE_HOME if set, otherwise ~/.cache/nixwrap.
    """
    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        base = Path(xdg_cache)
    else:
        base = Path.home() / ".cache"
    return base / "nixwrap"


def run_package(attr: str, args: list[str]) -> int:
    """Run a package by attribute name.

    Args:
        attr: Package attribute name (e.g., "ripgrep")
        args: Additional arguments to pass to the binary

    Returns:
        Exit code (only if exec fails)
    """
    from .backend import (
        _compute_closure,
        _fetch_all_packages,
    )

    # Query the index
    print(f"Looking up {attr}...", file=sys.stderr)
    index = _get_index()
    pkg = index.find_package(attr)
    if not pkg:
        print(f"Error: Package '{attr}' not found in nix-index", file=sys.stderr)
        return 1

    # Select primary binary
    primary_binary = select_primary_binary(pkg.binaries, pkg.name)
    command = primary_binary.command
    bin_relpath = primary_binary.path

    # Determine ld-linux path based on system
    if "aarch64" in pkg.system:
        ld_linux_relpath = "lib/ld-linux-aarch64.so.1"
    else:
        ld_linux_relpath = "lib/ld-linux-x86-64.so.2"
    ld_linux_name = Path(ld_linux_relpath).name

    # Setup cache
    cache_dir = get_cache_dir()
    nix_store = cache_dir / "nix" / "store"
    nix_store.mkdir(parents=True, exist_ok=True)

    cache_url = "https://cache.nixos.org"

    # Check if already cached
    store_name = Path(pkg.store_path).name
    extract_dir = nix_store / store_name
    binary_path = extract_dir / bin_relpath

    if not binary_path.exists():
        # Compute closure
        print(f"Computing closure for {pkg.store_path}...", file=sys.stderr)
        nar_hash, closure = _compute_closure(cache_url, pkg.store_path)

        if not nar_hash:
            print(f"Error: Could not fetch narinfo for {pkg.store_path}", file=sys.stderr)
            return 1

        # Fetch packages
        _fetch_all_packages(
            cache_url=cache_url,
            store_path=pkg.store_path,
            nar_hash=nar_hash,
            closure=closure,
            nix_store=nix_store,
            validate_binary=bin_relpath,
        )

    # Verify binary exists
    if not binary_path.exists():
        print(f"Error: Binary not found at {binary_path}", file=sys.stderr)
        return 1

    # Find ld-linux
    ld_linux_path = None
    for item in nix_store.iterdir():
        if "glibc" in item.name:
            candidate = item / ld_linux_relpath
            if candidate.exists():
                ld_linux_path = candidate
                break

    if not ld_linux_path:
        print(f"Error: ld-linux not found", file=sys.stderr)
        return 1

    # Collect library paths
    lib_paths = []
    for item in nix_store.iterdir():
        lib_dir = item / "lib"
        if lib_dir.exists():
            lib_paths.append(str(lib_dir))

    library_path = ":".join(lib_paths)

    # Execute
    print(f"Running {command}...", file=sys.stderr)
    os.execve(
        str(ld_linux_path),
        [str(ld_linux_path), "--library-path", library_path, str(binary_path)] + args,
        os.environ,
    )
    # execve doesn't return on success
    return 1


def show_info(attr: str) -> int:
    """Show information about a package.

    Args:
        attr: Package attribute name

    Returns:
        Exit code
    """
    index = _get_index()
    pkg = index.find_package(attr)
    if not pkg:
        print(f"Error: Package '{attr}' not found in nix-index", file=sys.stderr)
        return 1

    print(f"Package: {pkg.attr}")
    print(f"Name: {pkg.name}")
    print(f"Version: {pkg.version}")
    print(f"System: {pkg.system}")
    print(f"Store path: {pkg.store_path}")
    print(f"Binaries:")
    for binary in pkg.binaries:
        marker = " (primary)" if binary == select_primary_binary(pkg.binaries, pkg.name) else ""
        wrapper = " [wrapper]" if binary.is_wrapper else ""
        print(f"  - {binary.command}{wrapper}{marker}")

    return 0


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Run Nix packages without Nix installed",
        usage="nixwrap <package> [args...] | nixwrap {run,info} <package> [args...]",
    )
    parser.add_argument(
        "command",
        nargs="?",
        help="Command (run, info) or package name",
    )
    parser.add_argument(
        "package",
        nargs="?",
        help="Package name (when using run/info subcommand)",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the package",
    )

    # Handle the case where the first argument is a package name (not a subcommand)
    if len(sys.argv) < 2:
        parser.print_help()
        return 1

    first_arg = sys.argv[1]

    if first_arg in ("run", "info"):
        # Subcommand mode
        args = parser.parse_args()
        if not args.package:
            print(f"Error: {first_arg} requires a package name", file=sys.stderr)
            return 1

        if first_arg == "run":
            return run_package(args.package, args.args)
        elif first_arg == "info":
            return show_info(args.package)
    elif first_arg in ("-h", "--help"):
        parser.print_help()
        return 0
    else:
        # Direct package mode: nixwrap <package> [args...]
        return run_package(first_arg, sys.argv[2:])

    return 0


if __name__ == "__main__":
    sys.exit(main())
