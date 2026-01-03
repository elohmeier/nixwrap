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
import json
import os
import sys
from pathlib import Path

from .index import NixIndex, detect_system, select_primary_binary
from .patcher import collect_library_paths, find_absolute_store_paths, patch_binary


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


def _get_package_cache_path(attr: str) -> Path:
    """Get path to cached package metadata."""
    return get_cache_dir() / "packages" / f"{attr}.json"


def _load_cached_package(attr: str) -> dict | None:
    """Load cached package metadata if available."""
    cache_path = _get_package_cache_path(attr)
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _save_package_cache(attr: str, data: dict) -> None:
    """Save package metadata to cache."""
    cache_path = _get_package_cache_path(attr)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, indent=2))


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

    cache_url = "https://cache.nixos.org"

    # Setup cache directories
    cache_dir = get_cache_dir()
    nix_store = cache_dir / "nix" / "store"
    nix_store.mkdir(parents=True, exist_ok=True)

    # Try to load from package cache first
    cached = _load_cached_package(attr)

    if cached:
        # Use cached metadata
        store_path = cached["store_path"]
        command = cached["command"]
        bin_relpath = cached["bin_relpath"]
        ld_linux_relpath = cached["ld_linux_relpath"]
        nar_hash = cached["nar_hash"]
        closure = cached["closure"]
    else:
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
        store_path = pkg.store_path

        # Determine ld-linux path based on system
        if "aarch64" in pkg.system:
            ld_linux_relpath = "lib/ld-linux-aarch64.so.1"
        else:
            ld_linux_relpath = "lib/ld-linux-x86-64.so.2"

        # Compute closure
        print(f"Computing closure for {store_path}...", file=sys.stderr)
        nar_hash, closure = _compute_closure(cache_url, store_path)

        if not nar_hash:
            print(f"Error: Could not fetch narinfo for {store_path}", file=sys.stderr)
            return 1

        # Save to cache for next time
        _save_package_cache(
            attr,
            {
                "store_path": store_path,
                "command": command,
                "bin_relpath": bin_relpath,
                "ld_linux_relpath": ld_linux_relpath,
                "nar_hash": nar_hash,
                "closure": closure,
            },
        )

    # Check if already extracted
    store_name = Path(store_path).name
    extract_dir = nix_store / store_name
    binary_path = extract_dir / bin_relpath

    if not binary_path.exists():
        # Fetch packages
        _fetch_all_packages(
            cache_url=cache_url,
            store_path=store_path,
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
        print("Error: ld-linux not found", file=sys.stderr)
        return 1

    # Check for absolute /nix/store paths in NEEDED entries
    abs_paths = find_absolute_store_paths(binary_path)
    if abs_paths:
        print(
            f"Found {len(abs_paths)} absolute store path(s), patching...",
            file=sys.stderr,
        )

        # Ensure patchelf is available
        patchelf_in_store = any("patchelf" in item.name for item in nix_store.iterdir())
        if not patchelf_in_store:
            print("Fetching patchelf...", file=sys.stderr)
            # Query index for patchelf
            patchelf_pkg = index.find_package("patchelf") if "index" in dir() else None
            if not patchelf_pkg:
                tmp_index = _get_index()
                patchelf_pkg = tmp_index.find_package("patchelf")

            if patchelf_pkg:
                patchelf_nar_hash, patchelf_closure = _compute_closure(
                    cache_url, patchelf_pkg.store_path
                )
                _fetch_all_packages(
                    cache_url=cache_url,
                    store_path=patchelf_pkg.store_path,
                    nar_hash=patchelf_nar_hash,
                    closure=patchelf_closure,
                    nix_store=nix_store,
                )

        # Patch the binary
        if not patch_binary(binary_path, abs_paths, nix_store, ld_linux_path):
            print("Warning: Failed to patch some absolute paths", file=sys.stderr)

    # Collect library paths (including subdirectories for lua modules etc.)
    lib_paths = collect_library_paths(nix_store)
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
    print("Binaries:")
    for binary in pkg.binaries:
        marker = (
            " (primary)"
            if binary == select_primary_binary(pkg.binaries, pkg.name)
            else ""
        )
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
            # Strip leading '--' separator if present
            run_args = args.args
            if run_args and run_args[0] == "--":
                run_args = run_args[1:]
            return run_package(args.package, run_args)
        elif first_arg == "info":
            return show_info(args.package)
    elif first_arg in ("-h", "--help"):
        parser.print_help()
        return 0
    else:
        # Direct package mode: nixwrap <package> [args...]
        # Strip leading '--' separator if present
        pkg_args = sys.argv[2:]
        if pkg_args and pkg_args[0] == "--":
            pkg_args = pkg_args[1:]
        return run_package(first_arg, pkg_args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
