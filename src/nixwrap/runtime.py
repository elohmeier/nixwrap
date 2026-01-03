"""Runtime utilities for executing embedded binaries."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def exec_embedded(module_name: str, command: str) -> None:
    """Execute an embedded binary from a nixwrap package.

    Args:
        module_name: The Python module name (e.g., 'nixwrap_tool_ripgrep')
        command: The command name (e.g., 'rg')
    """
    # Find the binary relative to the calling module
    # The binary is stored at <module>/bin/<command>
    try:
        import importlib.util

        spec = importlib.util.find_spec(module_name)
        if spec is None or spec.origin is None:
            print(f"Error: Module {module_name} not found", file=sys.stderr)
            sys.exit(1)

        module_dir = Path(spec.origin).parent
        binary = module_dir / "bin" / command

        if not binary.exists():
            print(f"Error: Binary not found at {binary}", file=sys.stderr)
            sys.exit(1)

        # Replace the current process with the binary
        os.execv(str(binary), [str(binary)] + sys.argv[1:])

    except Exception as e:
        print(f"Error executing {command}: {e}", file=sys.stderr)
        sys.exit(1)
