# nixwrap

Run Nix packages from Python without Nix installed.

## Overview

nixwrap provides two ways to run Nix-built binaries:

1. **Direct CLI**: Run any package from nixpkgs instantly
2. **Python packages**: Install tools via pip/uv from a PEP 503 index

Both methods fetch binaries from the Nix binary cache, patch them for relocation, and run them using a bundled dynamic linker.

## Quick Start

### CLI (Recommended)

```bash
# Install nixwrap
pip install nixwrap

# Run any nixpkgs package directly
nixwrap ripgrep --version
nixwrap neovim-unwrapped --version
nixwrap jq --help

# Or use uvx for one-off execution
uvx nixwrap bat README.md
```

### Python Package Index

```bash
# Install a tool from the nixwrap index
uv tool install --index-url https://elohmeier.github.io/nixwrap/ ripgrep

# Use the tool
rg --version
```

## How It Works

1. **Package Discovery**: Queries the [nix-index-database](https://github.com/nix-community/nix-index-database) to find packages and their binaries
2. **Closure Computation**: Fetches narinfo files to compute the full dependency closure
3. **Binary Fetching**: Downloads and extracts NAR archives from the Nix binary cache
4. **Patching**: Uses patchelf to fix binaries with hardcoded `/nix/store` paths
5. **Execution**: Runs binaries via a bundled `ld-linux` with the correct library path

## Repository Structure

```
nixwrap/
  pyproject.toml              # Main package configuration
  src/nixwrap/
    __init__.py
    backend.py                # PEP 517 build backend for wheels
    cli.py                    # CLI entry point (nixwrap command)
    index.py                  # nix-index-database parser
    patcher.py                # ELF patching with patchelf
  nixwrap-index/              # Separate package containing nix-index data
    pyproject.toml
    src/nixwrap_index/
      __init__.py
      data/                   # Index files (downloaded in CI)
  tools/
    generate_stubs.py         # Generates stub sdists for PEP 503 index
  .github/workflows/
    publish-pages.yml         # Publishes stubs to GitHub Pages
    publish-pypi.yml          # Publishes nixwrap to PyPI
    publish-pypi-index.yml    # Publishes nixwrap-index to PyPI
```

## Requirements

- Python 3.14+ (for `compression.zstd` stdlib module)
- Linux x86_64 or aarch64

## Development

```bash
# Clone and setup
git clone https://github.com/elohmeier/nixwrap.git
cd nixwrap
uv sync

# Run the CLI locally
uv run nixwrap ripgrep --version

# Build wheels locally
uv build
```

## Limitations

- **Wrapper scripts**: Packages that use shell wrapper scripts (like `neovim`) won't work because they have hardcoded paths in bash scripts. Use the `-unwrapped` variant instead (e.g., `neovim-unwrapped`).
- **Linux only**: Currently only supports Linux (x86_64 and aarch64).
- **Python 3.14+**: Requires Python 3.14 for the stdlib zstd module.

## License

MIT
