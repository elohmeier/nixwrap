#!/usr/bin/env python3
"""Generate minimal stub sdists for all packages in nix-index.

Creates tiny sdists (~1KB each) with just pyproject.toml containing
[tool.nixwrap].attr. The actual package resolution happens at build time
when the user installs the package.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path

# Add parent directory to path for importing nixwrap
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nixwrap.index import NixIndex, select_primary_binary


def normalize_name(name: str) -> str:
    """Normalize distribution name for PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_module_name(name: str) -> str:
    """Normalize name for Python module."""
    return re.sub(r"[-_.]+", "_", name).lower()


def generate_stub_sdist(
    attr: str,
    command: str,
    version: str,
    output_dir: Path,
) -> Path | None:
    """Generate a minimal stub sdist for a package.

    Args:
        attr: The nixpkgs attribute name
        command: The primary command name
        version: Package version
        output_dir: Directory to write the sdist

    Returns:
        Path to the created sdist, or None on failure
    """
    # Use attr as dist name (what users search for, e.g. "ripgrep" not "rg")
    dist_name = attr
    normalized_name = normalize_name(dist_name)
    module_name = "nixwrap_tool_" + normalize_module_name(attr)

    # Create pyproject.toml content
    pyproject = f'''[build-system]
requires = ["nixwrap>=0.8"]
build-backend = "nixwrap.backend"

[project]
name = "{dist_name}"
version = "{version}"
description = "Nix package: {attr}"
requires-python = ">=3.14"

[project.scripts]
{command} = "{module_name}.runner:main"

[tool.nixwrap]
attr = "{attr}"
'''

    # Create PKG-INFO
    pkg_info = f"""Metadata-Version: 2.1
Name: {dist_name}
Version: {version}
Summary: Nix package: {attr}
Requires-Python: >=3.14
"""

    # Create minimal source files
    init_py = ""
    runner_py = f'''"""Runner placeholder for {command}."""
# Actual runner is generated at wheel build time
'''

    # Build the sdist tarball
    sdist_name = f"{normalized_name}-{version}.tar.gz"
    sdist_path = output_dir / sdist_name
    base_dir = f"{normalized_name}-{version}"

    try:
        with tarfile.open(sdist_path, "w:gz") as tar:
            # Add pyproject.toml
            data = pyproject.encode()
            info = tarfile.TarInfo(f"{base_dir}/pyproject.toml")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

            # Add PKG-INFO
            data = pkg_info.encode()
            info = tarfile.TarInfo(f"{base_dir}/PKG-INFO")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

            # Add src directory
            info = tarfile.TarInfo(f"{base_dir}/src/{module_name}")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)

            # Add __init__.py
            data = init_py.encode()
            info = tarfile.TarInfo(f"{base_dir}/src/{module_name}/__init__.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

            # Add runner.py
            data = runner_py.encode()
            info = tarfile.TarInfo(f"{base_dir}/src/{module_name}/runner.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        return sdist_path
    except Exception as e:
        print(f"  Error creating sdist for {attr}: {e}", file=sys.stderr)
        return None


def generate_pep503_index(packages_dir: Path, index_dir: Path) -> None:
    """Generate PEP 503 simple index HTML pages."""
    index_dir.mkdir(parents=True, exist_ok=True)

    packages: dict[str, list[Path]] = {}

    # Collect all tarballs
    for pkg_file in packages_dir.glob("*.tar.gz"):
        name = pkg_file.name.rsplit("-", 1)[0]
        normalized = normalize_name(name)
        if normalized not in packages:
            packages[normalized] = []
        packages[normalized].append(pkg_file)

    # Collect all wheels
    for pkg_file in packages_dir.glob("*.whl"):
        parts = pkg_file.name.split("-")
        name_parts = []
        for part in parts:
            if part[0].isdigit():
                break
            name_parts.append(part)
        name = "_".join(name_parts)
        normalized = normalize_name(name)
        if normalized not in packages:
            packages[normalized] = []
        packages[normalized].append(pkg_file)

    # Generate per-package index pages
    for name, pkg_files in packages.items():
        project_dir = index_dir / name
        project_dir.mkdir(parents=True, exist_ok=True)

        links = []
        for pkg_file in sorted(pkg_files):
            sha256 = hashlib.sha256(pkg_file.read_bytes()).hexdigest()
            rel_path = f"../packages/{pkg_file.name}"
            links.append(f'<a href="{rel_path}#sha256={sha256}">{pkg_file.name}</a>')

        html = f"""<!DOCTYPE html>
<html>
<head><title>Links for {name}</title></head>
<body>
<h1>Links for {name}</h1>
{chr(10).join(links)}
</body>
</html>
"""
        (project_dir / "index.html").write_text(html)

    # Generate root index
    root_links = [f'<a href="{name}/">{name}</a>' for name in sorted(packages.keys())]
    root_html = f"""<!DOCTYPE html>
<html>
<head><title>nixwrap Simple Index</title></head>
<body>
<h1>nixwrap Simple Index</h1>
<p>{len(packages)} packages available</p>
{chr(10).join(root_links)}
</body>
</html>
"""
    (index_dir / "index.html").write_text(root_html)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate stub sdists for all packages in nix-index"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("gh-pages"),
        help="Output directory for generated files",
    )
    parser.add_argument(
        "--system",
        default="x86_64-linux",
        help="Nix system to use for package discovery",
    )
    parser.add_argument(
        "--index-path",
        type=Path,
        help="Direct path to nix-index file (for testing without nixwrap-index installed)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of packages (0 for unlimited)",
    )
    args = parser.parse_args()

    packages_dir = args.output / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    # Determine index path
    index_path = args.index_path
    if not index_path:
        # Try default location in nixwrap-index package data
        default_path = Path(__file__).parent.parent / "nixwrap-index" / "src" / "nixwrap_index" / "data" / f"index-{args.system}"
        if default_path.exists():
            index_path = default_path

    print(f"Loading nix-index for {args.system}...", file=sys.stderr)
    index = NixIndex(args.system, index_path=index_path)
    index.load()

    all_attrs = index.list_packages()
    if args.limit > 0:
        all_attrs = all_attrs[: args.limit]

    print(f"Generating stubs for {len(all_attrs)} packages...", file=sys.stderr)

    successful = 0
    for i, attr in enumerate(all_attrs, 1):
        pkg = index.find_package(attr)
        if not pkg or not pkg.binaries:
            continue

        try:
            primary = select_primary_binary(pkg.binaries, pkg.name)
            command = primary.command
        except ValueError:
            continue

        sdist_path = generate_stub_sdist(
            attr=attr,
            command=command,
            version=pkg.version,
            output_dir=packages_dir,
        )

        if sdist_path:
            successful += 1
            if i % 100 == 0 or i == len(all_attrs):
                print(f"  [{i}/{len(all_attrs)}] {attr}", file=sys.stderr)

    print(f"\nGenerated {successful} stub sdists", file=sys.stderr)

    if successful > 0:
        print("Generating PEP 503 index...", file=sys.stderr)
        generate_pep503_index(packages_dir, args.output)
        print(f"Index written to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
