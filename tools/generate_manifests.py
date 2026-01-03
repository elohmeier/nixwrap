#!/usr/bin/env python3
"""Generate manifests by auto-discovering CLI tools from nix-index-database.

Downloads the latest nix-index-database and discovers packages that provide
binaries in bin/. Automatically detects Nix wrapper scripts.
"""

from __future__ import annotations

import json
import re
import struct
import sys
import tempfile
import urllib.request
from pathlib import Path

try:
    import zstandard
except ImportError:
    print("Please install zstandard: pip install zstandard", file=sys.stderr)
    sys.exit(1)

NIX_CACHE_URL = "https://cache.nixos.org"

# Packages to skip (known problematic or not useful as standalone CLI tools)
SKIP_PACKAGES = {
    "coreutils", "busybox", "toybox",  # Too many commands, conflicts
    "util-linux",  # System utilities
    "glibc", "gcc", "binutils",  # Build tools
    "bash", "zsh", "fish",  # Shells (complex setup)
    "python3", "nodejs", "ruby", "perl",  # Interpreters
    "go", "rustc", "cargo",  # Compilers
}


def download_nix_index(system: str, tmpdir: Path) -> Path:
    """Download latest nix-index-database for a system."""
    api_url = "https://api.github.com/repos/nix-community/nix-index-database/releases/latest"
    with urllib.request.urlopen(api_url) as resp:
        release = json.load(resp)

    tag = release["tag_name"]
    print(f"Latest release: {tag}", file=sys.stderr)

    asset_name = f"index-{system}"
    asset_url = None
    for asset in release["assets"]:
        if asset["name"] == asset_name:
            asset_url = asset["browser_download_url"]
            break

    if not asset_url:
        raise ValueError(f"No asset found for {system}")

    index_path = tmpdir / asset_name
    print(f"Downloading {asset_name}...", file=sys.stderr)
    urllib.request.urlretrieve(asset_url, index_path)
    print(f"Downloaded {index_path.stat().st_size / 1024 / 1024:.1f} MB", file=sys.stderr)

    return index_path


def discover_packages(index_path: Path) -> dict[str, dict]:
    """Parse nix-index database and discover packages with binaries.

    Returns dict of {attr: {store_path, name, system, binaries: [{path, is_wrapper}]}}
    """
    with open(index_path, "rb") as f:
        magic = f.read(4)
        if magic != b"NIXI":
            raise ValueError(f"Invalid magic: {magic}")
        f.read(8)  # version

        dctx = zstandard.ZstdDecompressor()
        reader = dctx.stream_reader(f)

        chunks = []
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)

    print(f"Decompressed {len(data) / 1024 / 1024:.1f} MB", file=sys.stderr)

    # Find package metadata
    packages = {}
    pkg_pattern = rb'\{"store_dir":"/nix/store","hash":"([a-z0-9]+)","name":"([^"]+)","origin":\{"attr":"([^"]+)","output":"([^"]+)","toplevel":(true|false),"system":"([^"]+)"\}\}'

    for match in re.finditer(pkg_pattern, data):
        hash_ = match.group(1).decode()
        name = match.group(2).decode()
        attr = match.group(3).decode()
        output = match.group(4).decode()
        toplevel = match.group(5) == b"true"
        system = match.group(6).decode()

        if not toplevel or output != "out":
            continue

        # Skip known problematic packages
        base_attr = attr.split(".")[-1]  # Handle python3Packages.foo etc
        if base_attr in SKIP_PACKAGES:
            continue

        packages[attr] = {
            "hash": hash_,
            "name": name,
            "system": system,
            "store_path": f"/nix/store/{hash_}-{name}",
            "binaries": [],
        }

    # Find binary files - look for paths containing /bin/
    # The format in the database has file paths after package info
    bin_pattern = rb'/nix/store/([a-z0-9]+)-([^/\x00]+)/bin/([^\x00/]+)'

    for match in re.finditer(bin_pattern, data):
        hash_ = match.group(1).decode()
        pkg_name = match.group(2).decode()
        bin_name = match.group(3).decode()

        # Find matching package by hash
        for attr, pkg in packages.items():
            if pkg["hash"] == hash_:
                # Check if this is a wrapper script
                is_wrapper = bin_name.startswith(".")
                if is_wrapper:
                    # .foo-wrapped -> foo is the command
                    cmd_name = bin_name[1:].replace("-wrapped", "")
                else:
                    cmd_name = bin_name

                pkg["binaries"].append({
                    "path": f"bin/{bin_name}",
                    "command": cmd_name,
                    "is_wrapper": is_wrapper,
                })
                break

    # Filter to packages with at least one binary
    packages = {k: v for k, v in packages.items() if v["binaries"]}

    print(f"Found {len(packages)} packages with binaries", file=sys.stderr)
    return packages


def select_primary_binary(pkg: dict) -> tuple[str, str] | None:
    """Select the primary binary for a package.

    Prefers wrapper scripts, then matches package name, then first binary.
    Returns (bin_path, command_name) or None.
    """
    binaries = pkg["binaries"]
    if not binaries:
        return None

    # Extract base package name (e.g., "ripgrep-14.1.0" -> "ripgrep")
    pkg_name = pkg["name"]
    base_name = re.sub(r"-\d+.*$", "", pkg_name)

    # First: prefer wrapper that matches package name
    for b in binaries:
        if b["is_wrapper"] and b["command"] == base_name:
            return b["path"], b["command"]

    # Second: prefer non-wrapper that matches package name
    for b in binaries:
        if not b["is_wrapper"] and b["command"] == base_name:
            return b["path"], b["command"]

    # Third: any wrapper
    for b in binaries:
        if b["is_wrapper"]:
            return b["path"], b["command"]

    # Fourth: any binary (prefer shorter names, likely the main command)
    binaries_sorted = sorted(binaries, key=lambda x: len(x["command"]))
    return binaries_sorted[0]["path"], binaries_sorted[0]["command"]


def fetch_narinfo(store_path: str) -> dict[str, str]:
    """Fetch narinfo from Nix cache."""
    store_hash = Path(store_path).name.split("-")[0]
    url = f"{NIX_CACHE_URL}/{store_hash}.narinfo"

    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            text = resp.read().decode()
    except urllib.error.HTTPError:
        return {}

    result = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def get_closure(store_path: str) -> list[dict]:
    """Get full transitive closure for a store path."""
    seen = set()
    closure = []
    queue = [store_path]
    main_name = Path(store_path).name

    while queue:
        current = queue.pop(0)
        current_name = Path(current).name

        if current_name in seen:
            continue
        seen.add(current_name)

        narinfo = fetch_narinfo(current)
        if not narinfo:
            continue

        if current_name != main_name:
            closure.append({
                "store_path": current,
                "nar_hash": narinfo.get("NarHash", ""),
            })

        refs = narinfo.get("References", "").split()
        for ref in refs:
            if ref not in seen:
                queue.append(f"/nix/store/{ref}")

    return closure


def make_dist_name(attr: str, command: str) -> str:
    """Generate a PyPI-compatible distribution name."""
    # Use the command name, but handle conflicts
    # e.g., fd -> fd-find (conflicts with existing fd package)
    known_renames = {
        "fd": "fd-find",
        "delta": "git-delta",
        "yq-go": "yq",
    }
    base = attr.split(".")[-1]  # Handle python3Packages.foo
    return known_renames.get(base, command)


def generate_manifest(attr: str, pkg: dict) -> dict | None:
    """Generate a manifest dict for a package."""
    binary = select_primary_binary(pkg)
    if not binary:
        return None

    bin_path, command = binary
    store_path = pkg["store_path"]

    narinfo = fetch_narinfo(store_path)
    if not narinfo:
        return None

    nar_hash = narinfo.get("NarHash", "")
    if not nar_hash:
        return None

    # Extract version
    name = pkg["name"]
    version_match = re.search(r"-(\d+\.\d+[.\d]*)", name)
    version = version_match.group(1) if version_match else "0.0.0"

    closure = get_closure(store_path)

    system = pkg.get("system", "x86_64-linux")
    if "aarch64" in system:
        ld_linux = "lib/ld-linux-aarch64.so.1"
    else:
        ld_linux = "lib/ld-linux-x86-64.so.2"

    dist_name = make_dist_name(attr, command)

    return {
        "name": attr,
        "version": version,
        "dist": dist_name,
        "command": command,
        "description": f"Nix package: {attr}",
        "store_path": store_path,
        "bin_relpath": bin_path,
        "cache_url": NIX_CACHE_URL,
        "nar_hash": nar_hash,
        "ld_linux": ld_linux,
        "closure": closure,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Auto-discover and generate manifests from nix-index-database")
    parser.add_argument(
        "--systems",
        nargs="+",
        default=["x86_64-linux", "aarch64-linux"],
        help="Systems to generate manifests for",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Limit number of packages (0 for unlimited)",
    )
    args = parser.parse_args()

    all_manifests: dict[str, dict[str, dict]] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        for system in args.systems:
            print(f"\n=== Processing {system} ===", file=sys.stderr)

            index_path = download_nix_index(system, tmpdir_path)
            packages = discover_packages(index_path)

            # Sort by package name for consistent ordering
            sorted_attrs = sorted(packages.keys())
            if args.limit > 0:
                sorted_attrs = sorted_attrs[:args.limit]

            print(f"Processing {len(sorted_attrs)} packages...", file=sys.stderr)

            for attr in sorted_attrs:
                pkg = packages[attr]
                print(f"  {attr}...", file=sys.stderr)

                manifest = generate_manifest(attr, pkg)
                if manifest:
                    if attr not in all_manifests:
                        all_manifests[attr] = {}
                    all_manifests[attr][system] = manifest

    print(f"\nGenerated manifests for {len(all_manifests)} packages", file=sys.stderr)
    print(json.dumps(all_manifests, indent=2))


if __name__ == "__main__":
    main()
