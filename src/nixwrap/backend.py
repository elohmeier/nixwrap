"""PEP 517 build backend for nixwrap packages.

This backend can either:
1. Read a nixwrap_manifest.json from the source tree (legacy)
2. Query nixwrap-index via [tool.nixwrap] in pyproject.toml (new)

Then fetches the binary from the Nix cache and builds a wheel
with the binary embedded.

Uses only Python stdlib for zero external dependencies (Python 3.14+).
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import io
import json
import lzma
import os
import platform
import random
import re
import stat
import struct
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

try:
    import compression.zstd as zstd_stdlib  # Python 3.14+
except ImportError:
    zstd_stdlib = None

try:
    import tomllib  # Python 3.11+
except ImportError:
    tomllib = None

# HTTP client configuration (inspired by nix-index)
HTTP_TIMEOUT = 30  # seconds
HTTP_MAX_RETRIES = 10
HTTP_MAX_RETRY_DELAY = 5.0  # seconds
HTTP_BASE_RETRY_DELAY = 0.1  # seconds

# NAR format constants
NAR_MAGIC = b"nix-archive-1"
NAR_VERSION_STRING = b"("

# Nix base32 alphabet (note: no e, o, t, u)
NIX32_ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"


def _nix32_decode(s: str) -> bytes:
    """Decode a nix32 (Nix's custom base32) encoded string to bytes.

    This matches the algorithm in Nix's libutil/hash.cc.
    """
    lookup = {c: i for i, c in enumerate(NIX32_ALPHABET)}

    # For SHA256 (32 bytes), we expect 52 characters
    hash_size = (len(s) * 5) // 8
    result = [0] * hash_size

    for n in range(len(s)):
        c = lookup.get(s[len(s) - n - 1])
        if c is None:
            raise ValueError(f"Invalid nix32 character: {s[len(s) - n - 1]}")
        b = n * 5
        i = b // 8
        j = b % 8
        result[i] |= (c << j) & 0xff
        if i + 1 < hash_size:
            result[i + 1] |= c >> (8 - j)

    return bytes(result)


def _read_string(data: io.BytesIO) -> bytes:
    """Read a NAR string (length-prefixed, 8-byte aligned)."""
    length_bytes = data.read(8)
    if len(length_bytes) < 8:
        raise ValueError("Unexpected end of NAR data")
    (length,) = struct.unpack("<Q", length_bytes)
    content = data.read(length)
    if len(content) < length:
        raise ValueError("Unexpected end of NAR data")
    # Skip padding to 8-byte alignment
    padding = (8 - (length % 8)) % 8
    data.read(padding)
    return content


def _expect_string(data: io.BytesIO, expected: bytes) -> None:
    """Read a string and verify it matches expected value."""
    actual = _read_string(data)
    if actual != expected:
        raise ValueError(f"Expected {expected!r}, got {actual!r}")


def _parse_nar_directory(data: io.BytesIO, base_path: Path) -> None:
    """Parse a NAR directory recursively."""
    while True:
        token = _read_string(data)
        if token == b")":
            break
        if token == b"entry":
            _expect_string(data, b"(")
            _expect_string(data, b"name")
            name = _read_string(data).decode("utf-8")
            _expect_string(data, b"node")
            _parse_nar_node(data, base_path / name)
            _expect_string(data, b")")
        else:
            raise ValueError(f"Unexpected token in directory: {token!r}")


def _parse_nar_node(data: io.BytesIO, path: Path) -> None:
    """Parse a single NAR node (file, directory, or symlink)."""
    _expect_string(data, b"(")
    _expect_string(data, b"type")
    node_type = _read_string(data)

    if node_type == b"regular":
        executable = False
        contents = b""
        while True:
            token = _read_string(data)
            if token == b")":
                break
            if token == b"executable":
                _expect_string(data, b"")
                executable = True
            elif token == b"contents":
                contents = _read_string(data)
            else:
                raise ValueError(f"Unexpected token in regular file: {token!r}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        if executable:
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    elif node_type == b"directory":
        path.mkdir(parents=True, exist_ok=True)
        _parse_nar_directory(data, path)

    elif node_type == b"symlink":
        _expect_string(data, b"target")
        target = _read_string(data).decode("utf-8")
        _expect_string(data, b")")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)

    else:
        raise ValueError(f"Unknown node type: {node_type!r}")


def _parse_nar(nar_data: bytes, output_dir: Path) -> None:
    """Parse a NAR archive and extract to output directory."""
    data = io.BytesIO(nar_data)
    _expect_string(data, NAR_MAGIC)
    _parse_nar_node(data, output_dir)


def _fetch_with_retry(url: str, description: str = "resource") -> bytes:
    """Fetch a URL with exponential backoff retry logic."""
    last_error = None

    for attempt in range(HTTP_MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip, deflate"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
                data = response.read()
                # Handle gzip encoding
                if response.headers.get("Content-Encoding") == "gzip":
                    import gzip
                    data = gzip.decompress(data)
                return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_error = e
            if attempt < HTTP_MAX_RETRIES - 1:
                # Exponential backoff with jitter
                delay = min(
                    HTTP_MAX_RETRY_DELAY,
                    HTTP_BASE_RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.1),
                )
                print(f"  Retry {attempt + 1}/{HTTP_MAX_RETRIES} for {description} after {delay:.2f}s: {e}", file=sys.stderr)
                time.sleep(delay)

    raise RuntimeError(f"Failed to fetch {description} after {HTTP_MAX_RETRIES} attempts: {last_error}")


def _fetch_narinfo(cache_url: str, store_path: str) -> dict[str, str]:
    """Fetch and parse narinfo from cache."""
    store_hash = Path(store_path).name.split("-")[0]
    narinfo_url = f"{cache_url}/{store_hash}.narinfo"

    data = _fetch_with_retry(narinfo_url, f"narinfo for {store_path}")

    result = {}
    for line in data.decode("utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def _fetch_nar(cache_url: str, nar_path: str, expected_hash: str | None = None) -> bytes:
    """Fetch and decompress NAR from cache."""
    nar_url = f"{cache_url}/{nar_path}"

    compressed_data = _fetch_with_retry(nar_url, f"NAR {nar_path}")

    # Decompress based on extension
    if nar_path.endswith(".xz"):
        nar_data = lzma.decompress(compressed_data)
    elif nar_path.endswith(".zst"):
        if zstd_stdlib:
            nar_data = zstd_stdlib.decompress(compressed_data)
        else:
            try:
                import zstandard
            except ImportError:
                raise ImportError("zstandard package or Python 3.14+ required for .zst NAR files")
            dctx = zstandard.ZstdDecompressor()
            nar_data = dctx.decompress(compressed_data)
    else:
        nar_data = compressed_data

    # Verify hash if provided
    if expected_hash:
        algo, expected = expected_hash.split(":", 1) if ":" in expected_hash else ("sha256", expected_hash)
        if algo == "sha256":
            actual_bytes = hashlib.sha256(nar_data).digest()
            # Determine format of expected hash and compare
            if len(expected) == 64:  # hex format
                expected_bytes = bytes.fromhex(expected)
            elif len(expected) == 52:  # nix32 format (32 bytes -> 52 chars in nix32)
                expected_bytes = _nix32_decode(expected)
            else:  # assume base64
                expected_bytes = base64.b64decode(expected)
            if actual_bytes != expected_bytes:
                raise ValueError(f"NAR hash mismatch: expected {expected_bytes.hex()}, got {actual_bytes.hex()}")

    return nar_data


def _fetch_file_listing(cache_url: str, store_path: str) -> dict[str, Any] | None:
    """Fetch file listing (.ls) from cache for pre-flight validation.

    Returns the parsed JSON file listing, or None if not available.
    """
    store_hash = Path(store_path).name.split("-")[0]

    # Try uncompressed first, then xz-compressed
    for suffix in [".ls", ".ls.xz"]:
        url = f"{cache_url}/{store_hash}{suffix}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
                data = response.read()
                if suffix == ".ls.xz":
                    data = lzma.decompress(data)
                # Decode with surrogateescape to handle non-UTF8 filenames
                text = data.decode("utf-8", errors="surrogateescape")
                return json.loads(text)
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, lzma.LZMAError):
            continue

    return None


def _fetch_package(
    cache_url: str,
    store_path: str,
    nar_hash: str | None,
    nix_store: Path,
) -> Path:
    """Fetch a single package from the cache and extract it.

    Returns the path to the extracted directory.
    """
    store_name = Path(store_path).name
    extract_dir = nix_store / store_name

    # Skip if already extracted (deduplication)
    if extract_dir.exists():
        return extract_dir

    narinfo = _fetch_narinfo(cache_url, store_path)
    nar_path = narinfo.get("URL")
    if not nar_path:
        raise ValueError(f"No URL in narinfo for {store_path}")

    file_hash = nar_hash or narinfo.get("NarHash")
    nar_data = _fetch_nar(cache_url, nar_path, file_hash)

    _parse_nar(nar_data, extract_dir)
    return extract_dir


def _fetch_all_packages(
    cache_url: str,
    store_path: str,
    nar_hash: str | None,
    closure: list[dict[str, str]],
    nix_store: Path,
    validate_binary: str | None = None,
) -> Path:
    """Fetch the main package and all closure dependencies in parallel.

    Uses ThreadPoolExecutor for parallel fetching with stdlib only.
    """
    # Optional pre-flight validation using .ls file
    if validate_binary:
        print(f"  Validating binary path: {validate_binary}", file=sys.stderr)
        listing = _fetch_file_listing(cache_url, store_path)
        if listing:
            # Navigate the listing to check if binary exists
            parts = validate_binary.split("/")
            node = listing
            for part in parts:
                if node.get("type") == "directory" and "entries" in node:
                    node = node["entries"].get(part)
                    if node is None:
                        raise FileNotFoundError(
                            f"Pre-flight validation failed: {validate_binary} not found in file listing"
                        )
                else:
                    break
            print(f"  Pre-flight validation passed", file=sys.stderr)

    # Build list of all packages to fetch
    packages = [(store_path, nar_hash)]
    for dep in closure:
        packages.append((dep["store_path"], dep.get("nar_hash")))

    print(f"  Fetching {len(packages)} packages in parallel...", file=sys.stderr)

    # Fetch all packages in parallel using ThreadPoolExecutor
    results: dict[str, Path] = {}
    errors: list[tuple[str, Exception]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_pkg = {
            executor.submit(_fetch_package, cache_url, pkg_path, pkg_hash, nix_store): pkg_path
            for pkg_path, pkg_hash in packages
        }

        for future in concurrent.futures.as_completed(future_to_pkg):
            pkg_path = future_to_pkg[future]
            try:
                results[pkg_path] = future.result()
            except Exception as e:
                errors.append((pkg_path, e))

    if errors:
        pkg_path, e = errors[0]
        raise RuntimeError(f"Failed to fetch {pkg_path}: {e}") from e

    # Return the main package directory
    return results[store_path]


def _get_platform_tag() -> str:
    """Get the wheel platform tag for the current system."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        # Use manylinux for broad compatibility
        if machine == "x86_64":
            return "manylinux_2_17_x86_64"
        elif machine == "aarch64":
            return "manylinux_2_17_aarch64"
        else:
            return f"linux_{machine}"
    elif system == "darwin":
        if machine == "arm64":
            return "macosx_11_0_arm64"
        else:
            return "macosx_10_9_x86_64"
    else:
        return f"{system}_{machine}"


def _normalize_name(name: str) -> str:
    """Normalize package name for wheel filename."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _normalize_dist_name(name: str) -> str:
    """Normalize distribution name for PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _get_nix_system() -> str:
    """Get the Nix system identifier for the current platform."""
    machine = platform.machine().lower()
    system = platform.system().lower()

    if system == "linux":
        if machine == "x86_64":
            return "x86_64-linux"
        elif machine == "aarch64":
            return "aarch64-linux"
    elif system == "darwin":
        if machine == "arm64":
            return "aarch64-darwin"
        else:
            return "x86_64-darwin"

    return f"{machine}-{system}"


def _read_manifest(source_dir: Path) -> dict[str, Any]:
    """Read the nixwrap manifest for the current platform from source directory."""
    nix_system = _get_nix_system()

    # Try architecture-specific manifest first
    arch_manifest_path = source_dir / f"nixwrap_manifest_{nix_system}.json"
    if arch_manifest_path.exists():
        return json.loads(arch_manifest_path.read_text())

    # Fall back to legacy single manifest (for backwards compatibility)
    manifest_path = source_dir / "nixwrap_manifest.json"
    if manifest_path.exists():
        return json.loads(manifest_path.read_text())

    # List available manifests for helpful error message
    available = list(source_dir.glob("nixwrap_manifest*.json"))
    if available:
        archs = [p.stem.replace("nixwrap_manifest_", "") for p in available]
        raise FileNotFoundError(
            f"No manifest for {nix_system}. Available: {', '.join(archs)}"
        )
    raise FileNotFoundError(f"No manifest found in {source_dir}")


def _read_pyproject(source_dir: Path) -> dict[str, Any]:
    """Read pyproject.toml from source directory."""
    pyproject_path = source_dir / "pyproject.toml"
    if not pyproject_path.exists():
        raise FileNotFoundError(f"No pyproject.toml found in {source_dir}")

    if tomllib:
        return tomllib.loads(pyproject_path.read_text())
    else:
        # Fallback: simple TOML parsing for [tool.nixwrap] section
        # This is a minimal parser for the specific format we need
        content = pyproject_path.read_text()
        result: dict[str, Any] = {"tool": {"nixwrap": {}}}
        in_nixwrap = False
        for line in content.splitlines():
            line = line.strip()
            if line == "[tool.nixwrap]":
                in_nixwrap = True
            elif line.startswith("["):
                in_nixwrap = False
            elif in_nixwrap and "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                result["tool"]["nixwrap"][key] = value
        return result


def _compute_closure(
    cache_url: str,
    store_path: str,
    max_workers: int = 16,
) -> tuple[str, list[dict[str, str]]]:
    """Compute transitive closure by walking narinfo References.

    Returns:
        Tuple of (main_nar_hash, closure_list)
    """
    seen: set[str] = set()
    closure: list[dict[str, str]] = []
    queue = [store_path]
    main_name = Path(store_path).name
    main_nar_hash = ""

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
            futures = {executor.submit(_fetch_narinfo, cache_url, p): p for p in batch}
            for future in concurrent.futures.as_completed(futures):
                path = futures[future]
                name = Path(path).name
                try:
                    narinfo = future.result()
                except Exception as e:
                    print(f"  Warning: Failed to fetch narinfo for {name}: {e}", file=sys.stderr)
                    continue

                if not narinfo:
                    print(f"  Warning: Empty narinfo for {name}", file=sys.stderr)
                    continue

                nar_hash = narinfo.get("NarHash", "")

                if name == main_name:
                    main_nar_hash = nar_hash
                else:
                    closure.append({
                        "store_path": path,
                        "nar_hash": nar_hash,
                    })

                refs = narinfo.get("References", "").split()
                for ref in refs:
                    if ref not in seen:
                        queue.append(f"/nix/store/{ref}")

    return main_nar_hash, closure


def _build_manifest_from_index(source_dir: Path) -> dict[str, Any]:
    """Build a manifest by querying nixwrap-index.

    Reads [tool.nixwrap] from pyproject.toml, queries the index,
    and computes closure at build time.
    """
    from .index import NixIndex, select_primary_binary

    pyproject = _read_pyproject(source_dir)
    nixwrap_config = pyproject.get("tool", {}).get("nixwrap", {})

    attr = nixwrap_config.get("attr")
    if not attr:
        raise ValueError("No [tool.nixwrap].attr found in pyproject.toml")

    cache_url = nixwrap_config.get("cache_url", "https://cache.nixos.org")

    print(f"  Querying nix-index for {attr}...", file=sys.stderr)
    index = NixIndex()
    pkg = index.find_package(attr)
    if not pkg:
        raise ValueError(f"Package {attr} not found in nix-index")

    # Select primary binary
    primary_binary = select_primary_binary(pkg.binaries, pkg.name)

    # Compute closure by fetching narinfo and walking References
    print(f"  Computing closure for {pkg.store_path}...", file=sys.stderr)
    try:
        nar_hash, closure = _compute_closure(cache_url, pkg.store_path)
    except Exception as e:
        print(f"  Error computing closure: {e}", file=sys.stderr)
        raise

    print(f"  Closure computed: nar_hash={nar_hash[:20] if nar_hash else 'EMPTY'}..., {len(closure)} deps", file=sys.stderr)

    if not nar_hash:
        raise ValueError(f"Could not fetch narinfo for {pkg.store_path}")

    # Determine ld-linux path based on system
    if "aarch64" in pkg.system:
        ld_linux = "lib/ld-linux-aarch64.so.1"
    else:
        ld_linux = "lib/ld-linux-x86-64.so.2"

    # Get dist name from pyproject or derive from attr
    project = pyproject.get("project", {})
    dist_name = project.get("name", attr)

    return {
        "name": attr,
        "dist": dist_name,
        "version": pkg.version,
        "command": primary_binary.command,
        "description": f"Nix package: {attr}",
        "store_path": pkg.store_path,
        "bin_relpath": primary_binary.path,
        "cache_url": cache_url,
        "nar_hash": nar_hash,
        "ld_linux": ld_linux,
        "closure": closure,
    }


def _get_module_name(manifest: dict[str, Any]) -> str:
    """Get the Python module name from manifest."""
    return "nixwrap_tool_" + re.sub(r"[-_.]+", "_", manifest["name"]).lower()


def _collect_libs(extract_dir: Path) -> list[tuple[str, bytes]]:
    """Collect all .so files from an extracted NAR directory."""
    libs = []
    lib_dir = extract_dir / "lib"
    if lib_dir.exists():
        for so_file in lib_dir.rglob("*.so*"):
            if so_file.is_file() and not so_file.is_symlink():
                rel_path = so_file.relative_to(extract_dir)
                libs.append((str(rel_path), so_file.read_bytes()))
            elif so_file.is_symlink():
                # Preserve symlinks by storing target
                rel_path = so_file.relative_to(extract_dir)
                target = os.readlink(so_file)
                libs.append((str(rel_path), ("symlink", target)))
    return libs


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    """PEP 517 build_wheel hook."""
    wheel_dir = Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)

    source_dir = Path.cwd()

    # Try new approach: query nixwrap-index via [tool.nixwrap]
    try:
        pyproject = _read_pyproject(source_dir)
        if pyproject.get("tool", {}).get("nixwrap", {}).get("attr"):
            manifest = _build_manifest_from_index(source_dir)
        else:
            # Fall back to legacy manifest files
            manifest = _read_manifest(source_dir)
    except FileNotFoundError:
        # No pyproject.toml, try legacy manifest
        manifest = _read_manifest(source_dir)

    dist_name = manifest["dist"]
    version = manifest["version"]
    command = manifest["command"]
    store_path = manifest["store_path"]
    bin_relpath = manifest["bin_relpath"]
    cache_url = manifest.get("cache_url", "https://cache.nixos.org")
    nar_hash = manifest.get("nar_hash")
    ld_linux_relpath = manifest.get("ld_linux", "lib/ld-linux-x86-64.so.2")
    ld_linux_name = Path(ld_linux_relpath).name  # e.g., "ld-linux-x86-64.so.2"
    closure = manifest.get("closure", [])

    module_name = _get_module_name(manifest)
    normalized_name = _normalize_name(dist_name)
    platform_tag = _get_platform_tag()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        nix_store = tmpdir_path / "nix" / "store"
        nix_store.mkdir(parents=True)

        # Fetch and extract main package and all closure dependencies in parallel
        main_extract_dir = _fetch_all_packages(
            cache_url=cache_url,
            store_path=store_path,
            nar_hash=nar_hash,
            closure=closure,
            nix_store=nix_store,
            validate_binary=bin_relpath,  # Pre-flight validation
        )

        # Find the binary
        binary_path = main_extract_dir / bin_relpath
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found at {bin_relpath}")

        # Find ld-linux in the glibc package
        ld_linux_path = None
        for item in nix_store.iterdir():
            if "glibc" in item.name:
                candidate = item / ld_linux_relpath
                if candidate.exists():
                    ld_linux_path = candidate
                    break

        if not ld_linux_path:
            raise FileNotFoundError(f"ld-linux not found at {ld_linux_relpath}")

        # Build the wheel
        wheel_name = f"{normalized_name}-{version}-py3-none-{platform_tag}.whl"
        wheel_path = wheel_dir / wheel_name

        with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as whl:
            # Write the module __init__.py
            whl.writestr(f"{module_name}/__init__.py", "")

            # Write the runner module that uses bundled ld-linux
            runner_code = f'''"""Runner for {command}."""

import os
import re
import sys
from pathlib import Path


def _setup_lib_symlinks(lib_dir: Path) -> None:
    """Create soname symlinks for versioned libraries.

    e.g., libfoo.so.1.2.3 -> libfoo.so.1, libfoo.so
    """
    for lib in lib_dir.glob("*.so.*"):
        name = lib.name
        # Skip non-.so files
        if not re.match(r".*\\.so\\.[0-9]", name):
            continue
        # Match libXXX.so.MAJOR.MINOR.PATCH or libXXX.so.MAJOR
        # Note: [^.]+ doesn't work for names like libstdc++, so use .+?
        match = re.match(r"(lib.+?\\.so)\\.([0-9]+)(\\.[0-9.]+)?$", name)
        if match:
            base, major, rest = match.groups()
            # Create libXXX.so.MAJOR symlink if versioned file exists
            soname = f"{{base}}.{{major}}"
            soname_path = lib_dir / soname
            if not soname_path.exists():
                try:
                    soname_path.symlink_to(name)
                except OSError:
                    pass  # May fail if read-only or already exists


def main() -> None:
    """Execute the embedded binary using bundled dynamic linker."""
    pkg_dir = Path(__file__).parent
    lib_dir = pkg_dir / "lib"
    bin_dir = pkg_dir / "bin"

    ld_linux = lib_dir / "{ld_linux_name}"
    binary = bin_dir / "{command}"

    if not ld_linux.exists():
        print(f"Error: ld-linux not found at {{ld_linux}}", file=sys.stderr)
        sys.exit(1)

    if not binary.exists():
        print(f"Error: Binary not found at {{binary}}", file=sys.stderr)
        sys.exit(1)

    # Create soname symlinks if needed
    _setup_lib_symlinks(lib_dir)

    # Execute via ld-linux with library path
    os.execve(
        str(ld_linux),
        [str(ld_linux), "--library-path", str(lib_dir), str(binary)] + sys.argv[1:],
        os.environ
    )


if __name__ == "__main__":
    main()
'''
            whl.writestr(f"{module_name}/runner.py", runner_code)

            # Collect only the essential files:
            # 1. The main binary
            # 2. ld-linux
            # 3. Required .so files from lib/ directories (real files only, not symlinks)

            # Write the binary
            bin_arc_path = f"{module_name}/bin/{command}"
            info = zipfile.ZipInfo(bin_arc_path)
            info.external_attr = (stat.S_IFREG | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
            whl.writestr(info, binary_path.read_bytes())

            # Write ld-linux
            ld_arc_path = f"{module_name}/lib/{ld_linux_name}"
            info = zipfile.ZipInfo(ld_arc_path)
            info.external_attr = (stat.S_IFREG | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
            whl.writestr(info, ld_linux_path.read_bytes())

            # Collect all .so files from lib/ directories (only real files)
            seen_libs = {ld_linux_name}  # Already added above
            for store_item in nix_store.iterdir():
                lib_dir = store_item / "lib"
                if not lib_dir.exists():
                    continue
                for so_file in lib_dir.glob("*.so*"):
                    if so_file.is_symlink():
                        continue  # Skip symlinks
                    if not so_file.is_file():
                        continue
                    name = so_file.name
                    # Skip non-.so files that match the glob (like .py files)
                    if not re.match(r".*\.so(\.[0-9.]+)?$", name):
                        continue
                    if name in seen_libs:
                        continue
                    seen_libs.add(name)

                    arc_path = f"{module_name}/lib/{name}"
                    info = zipfile.ZipInfo(arc_path)
                    info.external_attr = (stat.S_IFREG | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH) << 16
                    whl.writestr(info, so_file.read_bytes())

            # Write dist-info
            dist_info = f"{normalized_name}-{version}.dist-info"

            # METADATA
            metadata = f"""Metadata-Version: 2.1
Name: {dist_name}
Version: {version}
Summary: {manifest.get('description', f'nixwrap package for {command}')}
"""
            whl.writestr(f"{dist_info}/METADATA", metadata)

            # WHEEL
            wheel_metadata = f"""Wheel-Version: 1.0
Generator: nixwrap
Root-Is-Purelib: false
Tag: py3-none-{platform_tag}
"""
            whl.writestr(f"{dist_info}/WHEEL", wheel_metadata)

            # entry_points.txt
            entry_points = f"""[console_scripts]
{command} = {module_name}.runner:main
"""
            whl.writestr(f"{dist_info}/entry_points.txt", entry_points)

            # RECORD (must be last, includes hashes of all files)
            # Use csv module for proper escaping
            import csv as csv_module
            record_buffer = io.StringIO()
            writer = csv_module.writer(record_buffer, lineterminator="\n")
            for item in whl.namelist():
                if item.endswith("/RECORD"):
                    continue
                data = whl.read(item)
                digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                writer.writerow([item, f"sha256={digest}", str(len(data))])
            writer.writerow([f"{dist_info}/RECORD", "", ""])
            whl.writestr(f"{dist_info}/RECORD", record_buffer.getvalue())

    return wheel_name


def build_sdist(
    sdist_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    """PEP 517 build_sdist hook."""
    sdist_dir = Path(sdist_directory)
    sdist_dir.mkdir(parents=True, exist_ok=True)

    source_dir = Path.cwd()
    manifest = _read_manifest(source_dir)

    dist_name = manifest["dist"]
    version = manifest["version"]
    normalized_name = _normalize_dist_name(dist_name)

    sdist_name = f"{normalized_name}-{version}.tar.gz"
    sdist_path = sdist_dir / sdist_name

    module_name = _get_module_name(manifest)

    with tarfile.open(sdist_path, "w:gz") as tar:
        base_dir = f"{normalized_name}-{version}"

        # Add manifest
        manifest_data = json.dumps(manifest, indent=2).encode()
        info = tarfile.TarInfo(f"{base_dir}/nixwrap_manifest.json")
        info.size = len(manifest_data)
        tar.addfile(info, io.BytesIO(manifest_data))

        # Add pyproject.toml
        pyproject = f"""[build-system]
requires = ["nixwrap"]
build-backend = "nixwrap.backend"

[project]
name = "{dist_name}"
version = "{version}"
description = "{manifest.get('description', f'nixwrap package for {manifest["command"]}')})"
requires-python = ">=3.10"

[project.scripts]
{manifest["command"]} = "{module_name}.runner:main"
"""
        pyproject_data = pyproject.encode()
        info = tarfile.TarInfo(f"{base_dir}/pyproject.toml")
        info.size = len(pyproject_data)
        tar.addfile(info, io.BytesIO(pyproject_data))

        # Add PKG-INFO
        pkg_info = f"""Metadata-Version: 2.1
Name: {dist_name}
Version: {version}
Summary: {manifest.get('description', f'nixwrap package for {manifest["command"]}')}
"""
        pkg_info_data = pkg_info.encode()
        info = tarfile.TarInfo(f"{base_dir}/PKG-INFO")
        info.size = len(pkg_info_data)
        tar.addfile(info, io.BytesIO(pkg_info_data))

        # Add module directory
        info = tarfile.TarInfo(f"{base_dir}/src/{module_name}")
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        tar.addfile(info)

        # Add __init__.py
        init_data = b""
        info = tarfile.TarInfo(f"{base_dir}/src/{module_name}/__init__.py")
        info.size = 0
        tar.addfile(info, io.BytesIO(init_data))

        # Add runner.py placeholder (actual binary is fetched at wheel build time)
        runner_code = f'''"""Runner for {manifest["command"]}."""

import os
import sys
from pathlib import Path


def main() -> None:
    """Execute the embedded binary."""
    binary = Path(__file__).parent / "bin" / "{manifest["command"]}"
    if not binary.exists():
        print(f"Error: Binary not found at {{binary}}", file=sys.stderr)
        sys.exit(1)
    os.execv(str(binary), [str(binary)] + sys.argv[1:])


if __name__ == "__main__":
    main()
'''
        runner_data = runner_code.encode()
        info = tarfile.TarInfo(f"{base_dir}/src/{module_name}/runner.py")
        info.size = len(runner_data)
        tar.addfile(info, io.BytesIO(runner_data))

    return sdist_name


def get_requires_for_build_wheel(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    """PEP 517 hook to get build requirements for wheel."""
    return []  # No external dependencies - uses stdlib only


def get_requires_for_build_sdist(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    """PEP 517 hook to get build requirements for sdist."""
    return []
