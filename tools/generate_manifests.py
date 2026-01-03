#!/usr/bin/env python3
"""Generate manifests by auto-discovering CLI tools from nix-index-database.

Downloads the latest nix-index-database and discovers packages that provide
binaries in bin/. Automatically detects Nix wrapper scripts.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
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
    # Multi-binary packages that conflict
    "coreutils", "busybox", "toybox", "util-linux", "inetutils",
    # Build tools
    "glibc", "gcc", "binutils", "gnumake", "cmake", "meson", "ninja",
    # Shells
    "bash", "zsh", "fish", "dash", "tcsh", "ksh",
    # Interpreters/runtimes
    "python3", "python", "nodejs", "node", "ruby", "perl", "lua",
    # Compilers
    "go", "rustc", "cargo", "ghc", "ocaml",
    # System services
    "systemd", "dbus", "polkit", "udev",
}

# Binary names to skip (even if package is allowed)
SKIP_BINARIES = {"sh", "bash", "zsh", "fish", "python", "python3", "node", "perl", "ruby"}

# Pre-compiled regex patterns for speed
PKG_PATTERN = re.compile(
    rb'\{"store_dir":"/nix/store","hash":"([a-z0-9]+)","name":"([^"]+)",'
    rb'"origin":\{"attr":"([^"]+)","output":"([^"]+)","toplevel":(true|false),'
    rb'"system":"([^"]+)"\}\}'
)
# Binary names: match alphanumeric, dash, underscore, dot but stop before trailing 's' + null (format metadata)
BIN_PATTERN = re.compile(rb'/nix/store/([a-z0-9]{32})-[^/\x00]+/bin/(\.?[a-zA-Z0-9][a-zA-Z0-9._-]*?)(?=s?\x00)')


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

    Optimized version that processes data in chunks and uses hash lookup table.
    """
    with open(index_path, "rb") as f:
        magic = f.read(4)
        if magic != b"NIXI":
            raise ValueError(f"Invalid magic: {magic}")
        f.read(8)  # version

        dctx = zstandard.ZstdDecompressor()
        reader = dctx.stream_reader(f)

        # Read in chunks to avoid memory issues
        chunks = []
        while True:
            chunk = reader.read(4 * 1024 * 1024)  # 4MB chunks
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)

    print(f"Decompressed {len(data) / 1024 / 1024:.1f} MB", file=sys.stderr)

    # Pass 1: Build hash -> package info lookup (fast)
    print("  Finding packages...", file=sys.stderr)
    hash_to_pkg: dict[str, dict] = {}
    packages: dict[str, dict] = {}

    for match in PKG_PATTERN.finditer(data):
        hash_ = match.group(1).decode()
        name = match.group(2).decode()
        attr = match.group(3).decode()
        output = match.group(4).decode()
        toplevel = match.group(5) == b"true"
        system = match.group(6).decode()

        if not toplevel or output != "out":
            continue

        base_attr = attr.split(".")[-1]
        if base_attr in SKIP_PACKAGES:
            continue

        pkg_info = {
            "hash": hash_,
            "name": name,
            "system": system,
            "store_path": f"/nix/store/{hash_}-{name}",
            "binaries": [],
        }
        hash_to_pkg[hash_] = pkg_info
        packages[attr] = pkg_info

    print(f"  Found {len(packages)} toplevel packages", file=sys.stderr)

    # Pass 2: Find binaries using hash lookup (fast)
    print("  Finding binaries...", file=sys.stderr)
    for match in BIN_PATTERN.finditer(data):
        hash_ = match.group(1).decode()
        bin_name = match.group(2).decode()

        pkg = hash_to_pkg.get(hash_)
        if not pkg:
            continue

        is_wrapper = bin_name.startswith(".")
        if is_wrapper:
            cmd_name = bin_name[1:].replace("-wrapped", "")
        else:
            cmd_name = bin_name

        # Skip problematic binaries
        if cmd_name in SKIP_BINARIES:
            continue

        pkg["binaries"].append({
            "path": f"bin/{bin_name}",
            "command": cmd_name,
            "is_wrapper": is_wrapper,
        })

    # Filter to packages with binaries
    packages = {k: v for k, v in packages.items() if v["binaries"]}
    print(f"  {len(packages)} packages have binaries", file=sys.stderr)

    return packages


def select_primary_binary(pkg: dict) -> tuple[str, str] | None:
    """Select the primary binary for a package."""
    binaries = pkg["binaries"]
    if not binaries:
        return None

    pkg_name = pkg["name"]
    base_name = re.sub(r"-\d+.*$", "", pkg_name)

    # Prefer wrapper that matches package name
    for b in binaries:
        if b["is_wrapper"] and b["command"] == base_name:
            return b["path"], b["command"]

    # Non-wrapper matching package name
    for b in binaries:
        if not b["is_wrapper"] and b["command"] == base_name:
            return b["path"], b["command"]

    # Any wrapper
    for b in binaries:
        if b["is_wrapper"]:
            return b["path"], b["command"]

    # Shortest name (likely main command)
    binaries_sorted = sorted(binaries, key=lambda x: len(x["command"]))
    return binaries_sorted[0]["path"], binaries_sorted[0]["command"]


def fetch_narinfo(store_path: str) -> dict[str, str]:
    """Fetch narinfo from Nix cache."""
    store_hash = Path(store_path).name.split("-")[0]
    url = f"{NIX_CACHE_URL}/{store_hash}.narinfo"

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            text = resp.read().decode()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return {}

    result = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def get_closure_parallel(store_path: str, max_workers: int = 16) -> list[dict]:
    """Get transitive closure using parallel fetches."""
    seen: set[str] = set()
    closure: list[dict] = []
    queue = [store_path]
    main_name = Path(store_path).name

    while queue:
        # Fetch all current queue items in parallel
        batch = []
        while queue and len(batch) < max_workers * 2:
            path = queue.pop(0)
            name = Path(path).name
            if name not in seen:
                seen.add(name)
                batch.append(path)

        if not batch:
            break

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_narinfo, p): p for p in batch}
            for future in concurrent.futures.as_completed(futures):
                path = futures[future]
                name = Path(path).name
                try:
                    narinfo = future.result()
                except Exception:
                    continue

                if not narinfo:
                    continue

                if name != main_name:
                    closure.append({
                        "store_path": path,
                        "nar_hash": narinfo.get("NarHash", ""),
                    })

                refs = narinfo.get("References", "").split()
                for ref in refs:
                    if ref not in seen:
                        queue.append(f"/nix/store/{ref}")

    return closure


def make_dist_name(attr: str, command: str) -> str:
    """Generate a PyPI-compatible distribution name."""
    known_renames = {
        "fd": "fd-find",
        "delta": "git-delta",
        "yq-go": "yq",
    }
    base = attr.split(".")[-1]
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

    name = pkg["name"]
    version_match = re.search(r"-(\d+\.\d+[.\d]*)", name)
    version = version_match.group(1) if version_match else "0.0.0"

    closure = get_closure_parallel(store_path)

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


def generate_manifests_parallel(
    packages: dict[str, dict],
    attrs: list[str],
    max_workers: int = 8,
) -> dict[str, dict]:
    """Generate manifests for multiple packages in parallel."""
    results = {}

    def process_pkg(attr: str) -> tuple[str, dict | None]:
        pkg = packages[attr]
        manifest = generate_manifest(attr, pkg)
        return attr, manifest

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_pkg, attr): attr for attr in attrs}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            attr, manifest = future.result()
            if manifest:
                results[attr] = manifest
            print(f"  [{done}/{len(attrs)}] {attr}", file=sys.stderr)

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Auto-discover and generate manifests")
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
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of parallel workers for manifest generation",
    )
    args = parser.parse_args()

    all_manifests: dict[str, dict[str, dict]] = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        for system in args.systems:
            print(f"\n=== Processing {system} ===", file=sys.stderr)

            index_path = download_nix_index(system, tmpdir_path)
            packages = discover_packages(index_path)

            sorted_attrs = sorted(packages.keys())
            if args.limit > 0:
                sorted_attrs = sorted_attrs[:args.limit]

            print(f"Generating manifests for {len(sorted_attrs)} packages...", file=sys.stderr)

            manifests = generate_manifests_parallel(packages, sorted_attrs, args.workers)
            for attr, manifest in manifests.items():
                if attr not in all_manifests:
                    all_manifests[attr] = {}
                all_manifests[attr][system] = manifest

    print(f"\nGenerated manifests for {len(all_manifests)} packages", file=sys.stderr)
    print(json.dumps(all_manifests, indent=2))


if __name__ == "__main__":
    main()
