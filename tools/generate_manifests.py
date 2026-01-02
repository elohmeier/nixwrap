#!/usr/bin/env python3
"""Generate manifests from nix-index-database.

Downloads the latest nix-index-database release and generates
manifests for popular CLI tools.
"""

from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# Optional zstandard - will error if not available
try:
    import zstandard
except ImportError:
    print("Please install zstandard: pip install zstandard", file=sys.stderr)
    sys.exit(1)

# Popular CLI tools to package
# Format: (nixpkgs_attr, command_name, pypi_dist_name, bin_path_override)
# bin_path_override is used for packages with wrapper scripts (e.g., .bat-wrapped)
# Set to None to use default "bin/<command>"
TOOLS = [
    # Core utilities - known to work without wrappers
    ("ripgrep", "rg", "ripgrep", None),
    ("fd", "fd", "fd-find", None),
    ("sd", "sd", "sd", None),
    ("jq", "jq", "jq", None),
    ("yq-go", "yq", "yq", None),
    ("hexyl", "hexyl", "hexyl", None),
    ("hyperfine", "hyperfine", "hyperfine", None),
    ("tokei", "tokei", "tokei", None),
    ("dust", "dust", "dust", None),  # nixpkgs attr is "dust" not "du-dust"
    ("duf", "duf", "duf", None),
    ("procs", "procs", "procs", None),
    ("bottom", "btm", "bottom", None),
    ("zoxide", "zoxide", "zoxide", None),
    ("tealdeer", "tldr", "tealdeer", None),
    ("difftastic", "difft", "difftastic", None),
    ("delta", "delta", "git-delta", None),
    ("xh", "xh", "xh", None),
    ("grex", "grex", "grex", None),
    ("watchexec", "watchexec", "watchexec", None),
    ("just", "just", "just", None),
    ("atuin", "atuin", "atuin", None),
    ("mcfly", "mcfly", "mcfly", None),
    ("starship", "starship", "starship", None),
    ("lf", "lf", "lf", None),
    ("gdu", "gdu", "gdu", None),
    ("age", "age", "age", None),
    ("minisign", "minisign", "minisign", None),
    ("sops", "sops", "sops", None),
    ("restic", "restic", "restic", None),
    ("rclone", "rclone", "rclone", None),
    ("lazygit", "lazygit", "lazygit", None),
    ("gitui", "gitui", "gitui", None),
    ("gh", "gh", "gh", None),
    ("glab", "glab", "glab", None),
    ("zellij", "zellij", "zellij", None),
    ("helix", "hx", "helix", None),
    ("nushell", "nu", "nushell", None),
    ("yazi", "yazi", "yazi", None),
    ("xplr", "xplr", "xplr", None),
    ("btop", "btop", "btop", None),
    ("ncdu", "ncdu", "ncdu", None),
    ("tree", "tree", "tree", None),
    ("pv", "pv", "pv", None),
    ("entr", "entr", "entr", None),
    ("viddy", "viddy", "viddy", None),
    # Tools with Nix wrapper scripts - need bin_path_override
    ("bat", "bat", "bat", "bin/.bat-wrapped"),
    ("eza", "eza", "eza", "bin/.eza-wrapped"),
    ("fzf", "fzf", "fzf", "bin/.fzf-wrapped"),
    ("broot", "broot", "broot", "bin/.broot-wrapped"),
    ("nnn", "nnn", "nnn", "bin/.nnn-wrapped"),
]

NIX_CACHE_URL = "https://cache.nixos.org"


def download_nix_index(system: str, tmpdir: Path) -> Path:
    """Download latest nix-index-database for a system."""
    # Get latest release
    api_url = "https://api.github.com/repos/nix-community/nix-index-database/releases/latest"
    with urllib.request.urlopen(api_url) as resp:
        release = json.load(resp)

    tag = release["tag_name"]
    print(f"Latest release: {tag}")

    # Find asset for this system
    asset_name = f"index-{system}"
    asset_url = None
    for asset in release["assets"]:
        if asset["name"] == asset_name:
            asset_url = asset["browser_download_url"]
            break

    if not asset_url:
        raise ValueError(f"No asset found for {system}")

    # Download
    index_path = tmpdir / asset_name
    print(f"Downloading {asset_name}...")
    urllib.request.urlretrieve(asset_url, index_path)
    print(f"Downloaded {index_path.stat().st_size / 1024 / 1024:.1f} MB")

    return index_path


def parse_nix_index(index_path: Path, wanted_attrs: set[str]) -> dict[str, dict]:
    """Parse nix-index database and extract specific packages."""
    with open(index_path, "rb") as f:
        magic = f.read(4)
        if magic != b"NIXI":
            raise ValueError(f"Invalid magic: {magic}")
        version = struct.unpack("<Q", f.read(8))[0]

        dctx = zstandard.ZstdDecompressor()
        reader = dctx.stream_reader(f)

        chunks = []
        while True:
            chunk = reader.read(1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)

    print(f"Decompressed {len(data) / 1024 / 1024:.1f} MB")

    # Find all package info entries
    packages = {}
    pattern = rb'\{"store_dir":"/nix/store","hash":"([a-z0-9]+)","name":"([^"]+)","origin":\{"attr":"([^"]+)","output":"([^"]+)","toplevel":(true|false),"system":"([^"]+)"\}\}'

    for match in re.finditer(pattern, data):
        hash_ = match.group(1).decode()
        name = match.group(2).decode()
        attr = match.group(3).decode()
        output = match.group(4).decode()
        toplevel = match.group(5) == b"true"
        system = match.group(6).decode()

        # Only want toplevel packages with "out" output
        if not toplevel or output != "out":
            continue

        # Check if this is one of our wanted packages (exact match only)
        if attr in wanted_attrs:
            packages[attr] = {
                "hash": hash_,
                "name": name,
                "system": system,
                "store_path": f"/nix/store/{hash_}-{name}",
            }

    return packages


def fetch_narinfo(store_path: str) -> dict[str, str]:
    """Fetch narinfo from Nix cache."""
    store_hash = Path(store_path).name.split("-")[0]
    url = f"{NIX_CACHE_URL}/{store_hash}.narinfo"

    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            text = resp.read().decode()
    except urllib.error.HTTPError as e:
        print(f"  Warning: Failed to fetch narinfo for {store_path}: {e}")
        return {}

    result = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def get_closure(store_path: str) -> list[dict]:
    """Get full transitive closure for a store path from narinfo References."""
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

        # Add to closure (skip main package)
        if current_name != main_name:
            closure.append({
                "store_path": current,
                "nar_hash": narinfo.get("NarHash", ""),
            })

        # Queue all references for recursive fetching
        refs = narinfo.get("References", "").split()
        for ref in refs:
            if ref not in seen:
                queue.append(f"/nix/store/{ref}")

    return closure


def generate_manifest(
    attr: str,
    command: str,
    dist_name: str,
    bin_path: str | None,
    pkg_info: dict,
    output_dir: Path,
) -> bool:
    """Generate a manifest file for a package."""
    store_path = pkg_info["store_path"]

    # Fetch narinfo for hash
    narinfo = fetch_narinfo(store_path)
    if not narinfo:
        print(f"  Skipping {attr}: no narinfo")
        return False

    nar_hash = narinfo.get("NarHash", "")
    if not nar_hash:
        print(f"  Skipping {attr}: no NarHash")
        return False

    # Extract version from name (e.g., "ripgrep-14.1.0" -> "14.1.0")
    name = pkg_info["name"]
    version_match = re.search(r"-(\d+\.\d+[.\d]*)", name)
    version = version_match.group(1) if version_match else "0.0.0"

    # Get closure
    print(f"  Fetching closure for {attr}...")
    closure = get_closure(store_path)

    # Use bin_path override if provided, otherwise default to bin/<command>
    bin_relpath = bin_path if bin_path else f"bin/{command}"

    # Set ld_linux based on system architecture
    system = pkg_info.get("system", "x86_64-linux")
    if "aarch64" in system:
        ld_linux = "lib/ld-linux-aarch64.so.1"
    else:
        ld_linux = "lib/ld-linux-x86-64.so.2"

    manifest = {
        "name": attr,
        "version": version,
        "dist": dist_name,
        "command": command,
        "description": f"Nix package: {attr}",
        "store_path": store_path,
        "bin_relpath": bin_relpath,
        "cache_url": NIX_CACHE_URL,
        "nar_hash": nar_hash,
        "ld_linux": ld_linux,
        "closure": closure,
    }

    # Write manifest
    manifest_path = output_dir / f"{attr}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"  Wrote {manifest_path}")

    return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate manifests from nix-index-database")
    parser.add_argument(
        "--system",
        default="x86_64-linux",
        help="System to generate manifests for",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("tools/manifests"),
        help="Output directory for manifests",
    )
    parser.add_argument(
        "--tools",
        nargs="*",
        help="Specific tools to generate (default: all)",
    )
    args = parser.parse_args()

    # Filter tools if specified
    tools = TOOLS
    if args.tools:
        tools = [t for t in TOOLS if t[0] in args.tools]

    wanted_attrs = {t[0] for t in tools}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Download nix-index
        index_path = download_nix_index(args.system, tmpdir_path)

        # Parse index
        print("Parsing index...")
        packages = parse_nix_index(index_path, wanted_attrs)
        print(f"Found {len(packages)} of {len(wanted_attrs)} requested packages")

        # Generate manifests
        args.output.mkdir(parents=True, exist_ok=True)

        success = 0
        for attr, command, dist_name, bin_path in tools:
            if attr not in packages:
                print(f"  Missing: {attr}")
                continue

            print(f"Generating manifest for {attr}...")
            if generate_manifest(attr, command, dist_name, bin_path, packages[attr], args.output):
                success += 1

        print(f"\nGenerated {success} manifests")

        # Report missing
        missing = wanted_attrs - set(packages.keys())
        if missing:
            print(f"Missing packages: {sorted(missing)}")


if __name__ == "__main__":
    main()
