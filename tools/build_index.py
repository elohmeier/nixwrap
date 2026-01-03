#!/usr/bin/env python3
"""Generate sdists and PEP 503 index from manifests.

Reads manifests from stdin (JSON format from generate_manifests.py) and:
1. Creates ephemeral wrapper projects in a temp directory
2. Builds sdists using `python -m build --sdist`
3. Copies sdists to the output packages directory
4. Generates PEP 503 simple index HTML pages
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def normalize_name(name: str) -> str:
    """Normalize distribution name for PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_module_name(name: str) -> str:
    """Normalize name for Python module."""
    return re.sub(r"[-_.]+", "_", name).lower()


def generate_wrapper_project(manifests: dict[str, dict[str, Any]], output_dir: Path) -> None:
    """Generate a minimal wrapper project for building an sdist.

    Args:
        manifests: Dict of {arch: manifest} where arch is like "x86_64-linux"
        output_dir: Directory to write the project to
    """
    manifest = next(iter(manifests.values()))
    dist_name = manifest["dist"]
    version = manifest["version"]
    command = manifest["command"]
    description = manifest.get("description", f"nixwrap package for {command}")
    module_name = "nixwrap_tool_" + normalize_module_name(manifest["name"])

    output_dir.mkdir(parents=True, exist_ok=True)
    src_dir = output_dir / "src" / module_name
    src_dir.mkdir(parents=True, exist_ok=True)

    # Write architecture-specific manifests
    for arch, arch_manifest in manifests.items():
        manifest_path = output_dir / f"nixwrap_manifest_{arch}.json"
        manifest_path.write_text(json.dumps(arch_manifest, indent=2))

    # Write pyproject.toml
    pyproject = f'''[build-system]
requires = ["nixwrap-core"]
build-backend = "nixwrap_core.backend"

[project]
name = "{dist_name}"
version = "{version}"
description = "{description}"
requires-python = ">=3.10"

[project.scripts]
{command} = "{module_name}.runner:main"
'''
    (output_dir / "pyproject.toml").write_text(pyproject)

    # Write __init__.py
    (src_dir / "__init__.py").write_text("")

    # Write runner.py
    runner = f'''"""Runner for {command}."""

import os
import sys
from pathlib import Path


def main() -> None:
    """Execute the embedded binary."""
    binary = Path(__file__).parent / "bin" / "{command}"
    if not binary.exists():
        print(f"Error: Binary not found at {{binary}}", file=sys.stderr)
        sys.exit(1)
    os.execv(str(binary), [str(binary)] + sys.argv[1:])


if __name__ == "__main__":
    main()
'''
    (src_dir / "runner.py").write_text(runner)


def build_sdist(project_dir: Path, output_dir: Path) -> Path | None:
    """Build an sdist from the project directory."""
    output_dir = output_dir.resolve()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(output_dir)],
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("Successfully built "):
                sdist_name = line.split("Successfully built ", 1)[1].strip()
                return output_dir / sdist_name
        sdists = sorted(output_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        if sdists:
            return sdists[0]
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error building sdist: {e.stderr or e.stdout}", file=sys.stderr)
        return None


def generate_pep503_index(packages_dir: Path, index_dir: Path) -> None:
    """Generate PEP 503 simple index HTML pages."""
    index_dir.mkdir(parents=True, exist_ok=True)

    packages: dict[str, list[Path]] = {}

    for pkg_file in packages_dir.glob("*.tar.gz"):
        name = pkg_file.name.rsplit("-", 1)[0]
        normalized = normalize_name(name)
        if normalized not in packages:
            packages[normalized] = []
        packages[normalized].append(pkg_file)

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

    root_links = [f'<a href="{name}/">{name}</a>' for name in sorted(packages.keys())]
    root_html = f"""<!DOCTYPE html>
<html>
<head><title>nixwrap Simple Index</title></head>
<body>
<h1>nixwrap Simple Index</h1>
{chr(10).join(root_links)}
</body>
</html>
"""
    (index_dir / "index.html").write_text(root_html)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sdists and PEP 503 index from manifests")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("gh-pages"),
        help="Output directory for generated files",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temporary build directories (for debugging)",
    )
    args = parser.parse_args()

    # Read manifests from stdin
    # Format: { "ripgrep": { "x86_64-linux": {...}, "aarch64-linux": {...} }, ... }
    try:
        all_manifests = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON on stdin: {e}", file=sys.stderr)
        return 1

    if not all_manifests:
        print("Warning: No manifests provided", file=sys.stderr)
        return 0

    print(f"Received manifests for {len(all_manifests)} packages")

    packages_dir = args.out / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    successful = 0
    with tempfile.TemporaryDirectory(delete=not args.keep_temp) as tmpdir:
        if args.keep_temp:
            print(f"Temporary directory: {tmpdir}")

        for pkg_name, arch_manifests in all_manifests.items():
            archs = ", ".join(sorted(arch_manifests.keys()))
            manifest = next(iter(arch_manifests.values()))
            dist = manifest["dist"]
            version = manifest["version"]
            print(f"Processing {dist} v{version} ({archs})...")

            project_name = normalize_name(dist)
            project_dir = Path(tmpdir) / project_name
            generate_wrapper_project(arch_manifests, project_dir)

            sdist_path = build_sdist(project_dir, packages_dir)
            if sdist_path:
                print(f"  Built: {sdist_path.name}")
                successful += 1
            else:
                print(f"  Failed to build sdist", file=sys.stderr)

    print(f"\nBuilt {successful}/{len(all_manifests)} sdists")

    if successful > 0:
        print("Generating PEP 503 index...")
        generate_pep503_index(packages_dir, args.out)
        print(f"Index written to {args.out}")

    # Succeed if at least 80% of packages built (some may fail due to cache issues)
    min_success = int(len(all_manifests) * 0.8)
    if successful < min_success:
        print(f"Error: Only {successful}/{len(all_manifests)} packages built (need at least {min_success})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
