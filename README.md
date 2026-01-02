# nixwrap

Wrap Nix binaries into Python packages for installation via `uv tool install`.

## Overview

nixwrap provides a way to distribute Nix-built binaries as Python packages. When a user installs a nixwrap package (e.g., `ripgrep`), the PEP 517 build backend:

1. Fetches the narinfo and nar from the Nix binary cache
2. Verifies the hash
3. Extracts the binary
4. Builds a wheel containing the binary as package data

## Usage

```bash
# Install a tool from the nixwrap index
uv tool install --index-url https://elohmeier.github.io/nixwrap/ ripgrep

# Use the tool
rg --version
```

## Repository Structure

```
nixwrap/
  pyproject.toml              # nixwrap-core (shared build backend)
  src/nixwrap_core/
    __init__.py
    backend.py                # PEP 517 build backend
    runtime.py                # Runtime binary executor
  tools/
    manifests/                # Tool manifest files
      ripgrep.json
      fd.json
    build_index.py            # Generates sdists + PEP 503 index
  .github/workflows/
    publish-pages.yml         # CI for publishing to GitHub Pages
```

## Adding a New Tool

1. Create a manifest file in `tools/manifests/<tool>.json`:

```json
{
  "name": "ripgrep",
  "version": "15.1.0",
  "dist": "ripgrep",
  "command": "rg",
  "description": "A line-oriented search tool",
  "store_path": "/nix/store/...-ripgrep-15.1.0",
  "bin_relpath": "bin/rg",
  "cache_url": "https://cache.nixos.org",
  "nar_hash": "sha256:...",
  "ld_linux": "lib/ld-linux-x86-64.so.2",
  "closure": [
    {"store_path": "/nix/store/...-glibc-2.40-66", "nar_hash": "sha256:..."},
    {"store_path": "/nix/store/...-pcre2-10.46", "nar_hash": "sha256:..."}
  ]
}
```

2. Push to main - CI will regenerate the index and publish.

## Development

```bash
# Install dependencies
uv sync

# Build the index locally
uv run python tools/build_index.py --manifests tools/manifests --out gh-pages

# Test a local install
uv tool install --index-url file://$(pwd)/gh-pages/ ripgrep
```

## How It Works

### Build Time (CI)

The `build_index.py` script:
1. Reads each manifest from `tools/manifests/*.json`
2. Creates ephemeral wrapper projects in a temp directory
3. Builds sdists using `python -m build --sdist`
4. Generates PEP 503 simple index HTML pages
5. Publishes to GitHub Pages

### Install Time (User)

When a user runs `uv tool install ripgrep`:
1. uv downloads the sdist from the PEP 503 index
2. The PEP 517 build backend (`nixwrap_core.backend`) is invoked
3. The backend fetches the nar files from the Nix cache (main package + closure)
4. The binary, dynamic linker, and libraries are extracted and embedded in the wheel
5. The wheel is installed with the command available on PATH
6. At runtime, the binary is invoked via the bundled dynamic linker

## License

MIT
