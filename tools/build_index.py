#!/usr/bin/env python3
"""Generate sdists and PEP 503 index from manifests.

This script:
1. Reads each manifest from the manifests directory
2. Creates ephemeral wrapper projects in a temp directory
3. Builds sdists using `python -m build --sdist`
4. Copies sdists to the output packages directory
5. Generates PEP 503 simple index HTML pages
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def normalize_name(name: str) -> str:
    """Normalize distribution name for PEP 503 (lowercase, collapse separators to -)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize_module_name(name: str) -> str:
    """Normalize name for Python module (lowercase, collapse separators to _)."""
    return re.sub(r"[-_.]+", "_", name).lower()


def generate_wrapper_project(manifests: dict[str, dict[str, Any]], output_dir: Path) -> None:
    """Generate a minimal wrapper project for building an sdist.

    Args:
        manifests: Dict of {arch: manifest} where arch is like "x86_64-linux"
        output_dir: Directory to write the project to
    """
    # Use any manifest for common fields
    manifest = next(iter(manifests.values()))
    dist_name = manifest["dist"]
    version = manifest["version"]
    command = manifest["command"]
    description = manifest.get("description", f"nixwrap package for {command}")
    module_name = "nixwrap_tool_" + normalize_module_name(manifest["name"])

    # Create project structure
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
    # Resolve to absolute path since we change cwd
    output_dir = output_dir.resolve()
    try:
        # Use --no-isolation so the build uses nixwrap-core from current environment
        result = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(output_dir)],
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        # Find the generated sdist by parsing the output
        for line in result.stdout.splitlines():
            if line.startswith("Successfully built "):
                sdist_name = line.split("Successfully built ", 1)[1].strip()
                return output_dir / sdist_name
        # Fallback: find newest tar.gz
        sdists = sorted(output_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        if sdists:
            return sdists[0]
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error building sdist: {e.stderr or e.stdout}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return None


def generate_pep503_index(packages_dir: Path, index_dir: Path) -> None:
    """Generate PEP 503 simple index HTML pages at root."""
    index_dir.mkdir(parents=True, exist_ok=True)

    # Group packages by normalized name
    packages: dict[str, list[Path]] = {}

    # Process sdists (name-version.tar.gz)
    for pkg_file in packages_dir.glob("*.tar.gz"):
        # Extract package name from filename (name-version.tar.gz)
        name = pkg_file.name.rsplit("-", 1)[0]  # Remove version
        normalized = normalize_name(name)
        if normalized not in packages:
            packages[normalized] = []
        packages[normalized].append(pkg_file)

    # Process wheels (name-version-python-abi-platform.whl)
    for pkg_file in packages_dir.glob("*.whl"):
        # Wheel filename: {distribution}-{version}(-{build tag})?-{python}-{abi}-{platform}.whl
        # Extract name by taking everything before the version pattern
        parts = pkg_file.name.split("-")
        # Find where version starts (first part that looks like a version number)
        name_parts = []
        for i, part in enumerate(parts):
            if part[0].isdigit():
                break
            name_parts.append(part)
        name = "_".join(name_parts)  # Wheel names use underscores
        normalized = normalize_name(name)
        if normalized not in packages:
            packages[normalized] = []
        packages[normalized].append(pkg_file)

    # Generate per-project index pages
    for name, pkg_files in packages.items():
        project_dir = index_dir / name
        project_dir.mkdir(parents=True, exist_ok=True)

        links = []
        for pkg_file in sorted(pkg_files):
            # Calculate SHA256 hash for PEP 503 compliance
            sha256 = hashlib.sha256(pkg_file.read_bytes()).hexdigest()
            # Relative path from <project>/ to packages/
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
{chr(10).join(root_links)}
</body>
</html>
"""
    (index_dir / "index.html").write_text(root_html)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sdists and PEP 503 index from manifests")
    parser.add_argument(
        "--manifests",
        type=Path,
        default=Path("tools/manifests"),
        help="Directory containing manifest JSON files",
    )
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

    manifests_dir = args.manifests
    output_dir = args.out

    if not manifests_dir.exists():
        print(f"Error: Manifests directory not found: {manifests_dir}", file=sys.stderr)
        return 1

    # Find all manifest files and group by (dist, version, arch)
    manifest_files = list(manifests_dir.glob("*.json"))
    manifest_files.extend(manifests_dir.glob("*/*.json"))  # Include arch subdirs
    if not manifest_files:
        print(f"Warning: No manifest files found in {manifests_dir}", file=sys.stderr)
        return 0

    # Group manifests by (dist, version) -> {arch: manifest_file}
    manifest_groups: dict[tuple[str, str], dict[str, Path]] = {}
    for mf in manifest_files:
        try:
            m = json.loads(mf.read_text())
            key = (m["dist"], m["version"])
            # Determine architecture from parent directory name
            arch = mf.parent.name if mf.parent.name in ("x86_64-linux", "aarch64-linux") else "x86_64-linux"
            if key not in manifest_groups:
                manifest_groups[key] = {}
            manifest_groups[key][arch] = mf
        except (json.JSONDecodeError, KeyError):
            pass

    print(f"Found {len(manifest_groups)} unique package(s) from {len(manifest_files)} manifest files")

    # Setup output directories
    packages_dir = output_dir / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    # Process each manifest group
    successful = 0
    with tempfile.TemporaryDirectory(delete=not args.keep_temp) as tmpdir:
        if args.keep_temp:
            print(f"Temporary directory: {tmpdir}")

        for (dist, version), arch_manifests in manifest_groups.items():
            archs = ", ".join(sorted(arch_manifests.keys()))
            print(f"Processing {dist} v{version} ({archs})...")

            # Load all manifests for this package
            manifests: dict[str, dict[str, Any]] = {}
            valid = True
            for arch, manifest_file in arch_manifests.items():
                try:
                    manifest = json.loads(manifest_file.read_text())
                except json.JSONDecodeError as e:
                    print(f"  Error parsing manifest {manifest_file}: {e}", file=sys.stderr)
                    valid = False
                    break

                # Validate required fields
                required_fields = ["name", "version", "dist", "command", "store_path", "bin_relpath"]
                missing = [f for f in required_fields if f not in manifest]
                if missing:
                    print(f"  Error: Missing required fields in {manifest_file}: {missing}", file=sys.stderr)
                    valid = False
                    break

                manifests[arch] = manifest

            if not valid:
                continue

            # Generate wrapper project with all arch manifests
            project_name = normalize_name(dist)
            project_dir = Path(tmpdir) / project_name
            generate_wrapper_project(manifests, project_dir)

            # Build sdist
            sdist_path = build_sdist(project_dir, packages_dir)
            if sdist_path:
                print(f"  Built: {sdist_path.name}")
                successful += 1
            else:
                print(f"  Failed to build sdist", file=sys.stderr)

    print(f"\nBuilt {successful}/{len(manifest_groups)} sdists")

    # Generate PEP 503 index at root
    if successful > 0:
        print("Generating PEP 503 index...")
        generate_pep503_index(packages_dir, output_dir)
        print(f"Index written to {output_dir}")

    return 0 if successful == len(manifest_files) else 1


if __name__ == "__main__":
    sys.exit(main())
