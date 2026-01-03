"""ELF binary patching for relocating Nix store paths.

This module provides functionality to detect and fix binaries that have
hardcoded /nix/store paths in their NEEDED entries, making them work
outside of the Nix store.
"""

from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path


# ELF constants
ELF_MAGIC = b"\x7fELF"
PT_DYNAMIC = 2
DT_NEEDED = 1
DT_NULL = 0
DT_STRTAB = 5


def _parse_elf_needed(binary_path: Path) -> list[str]:
    """Parse NEEDED entries from an ELF binary.

    Returns list of library names/paths from DT_NEEDED entries.
    This is a minimal ELF parser that only extracts what we need.
    """
    with open(binary_path, "rb") as f:
        # Check ELF magic
        magic = f.read(4)
        if magic != ELF_MAGIC:
            return []

        # Read ELF class (32 or 64 bit)
        f.seek(4)
        ei_class = ord(f.read(1))
        is_64bit = ei_class == 2

        # Read endianness
        ei_data = ord(f.read(1))
        endian = "<" if ei_data == 1 else ">"

        if is_64bit:
            # 64-bit ELF header
            f.seek(32)  # e_phoff
            phoff = struct.unpack(f"{endian}Q", f.read(8))[0]
            f.seek(54)  # e_phentsize
            phentsize = struct.unpack(f"{endian}H", f.read(2))[0]
            phnum = struct.unpack(f"{endian}H", f.read(2))[0]
        else:
            # 32-bit ELF header
            f.seek(28)  # e_phoff
            phoff = struct.unpack(f"{endian}I", f.read(4))[0]
            f.seek(42)  # e_phentsize
            phentsize = struct.unpack(f"{endian}H", f.read(2))[0]
            phnum = struct.unpack(f"{endian}H", f.read(2))[0]

        # Find PT_DYNAMIC segment
        dynamic_offset = 0
        dynamic_size = 0

        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            if is_64bit:
                p_type = struct.unpack(f"{endian}I", f.read(4))[0]
                f.read(4)  # p_flags
                p_offset = struct.unpack(f"{endian}Q", f.read(8))[0]
                f.read(8)  # p_vaddr
                f.read(8)  # p_paddr
                p_filesz = struct.unpack(f"{endian}Q", f.read(8))[0]
            else:
                p_type = struct.unpack(f"{endian}I", f.read(4))[0]
                p_offset = struct.unpack(f"{endian}I", f.read(4))[0]
                f.read(4)  # p_vaddr
                f.read(4)  # p_paddr
                p_filesz = struct.unpack(f"{endian}I", f.read(4))[0]

            if p_type == PT_DYNAMIC:
                dynamic_offset = p_offset
                dynamic_size = p_filesz
                break

        if dynamic_offset == 0:
            return []

        # Parse dynamic section to find STRTAB and NEEDED entries
        strtab_offset = 0
        needed_offsets = []

        f.seek(dynamic_offset)
        entry_size = 16 if is_64bit else 8
        num_entries = dynamic_size // entry_size

        for _ in range(num_entries):
            if is_64bit:
                d_tag = struct.unpack(f"{endian}Q", f.read(8))[0]
                d_val = struct.unpack(f"{endian}Q", f.read(8))[0]
            else:
                d_tag = struct.unpack(f"{endian}I", f.read(4))[0]
                d_val = struct.unpack(f"{endian}I", f.read(4))[0]

            if d_tag == DT_NULL:
                break
            elif d_tag == DT_STRTAB:
                strtab_offset = d_val
            elif d_tag == DT_NEEDED:
                needed_offsets.append(d_val)

        if strtab_offset == 0:
            return []

        # Find the string table in the file
        # We need to convert virtual address to file offset
        # Find the segment containing the strtab
        strtab_file_offset = 0
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            if is_64bit:
                p_type = struct.unpack(f"{endian}I", f.read(4))[0]
                f.read(4)  # p_flags
                p_offset = struct.unpack(f"{endian}Q", f.read(8))[0]
                p_vaddr = struct.unpack(f"{endian}Q", f.read(8))[0]
                f.read(8)  # p_paddr
                p_filesz = struct.unpack(f"{endian}Q", f.read(8))[0]
                p_memsz = struct.unpack(f"{endian}Q", f.read(8))[0]
            else:
                p_type = struct.unpack(f"{endian}I", f.read(4))[0]
                p_offset = struct.unpack(f"{endian}I", f.read(4))[0]
                p_vaddr = struct.unpack(f"{endian}I", f.read(4))[0]
                f.read(4)  # p_paddr
                p_filesz = struct.unpack(f"{endian}I", f.read(4))[0]
                p_memsz = struct.unpack(f"{endian}I", f.read(4))[0]

            if p_vaddr <= strtab_offset < p_vaddr + p_memsz:
                strtab_file_offset = p_offset + (strtab_offset - p_vaddr)
                break

        if strtab_file_offset == 0:
            return []

        # Read NEEDED strings
        needed = []
        for offset in needed_offsets:
            f.seek(strtab_file_offset + offset)
            name = b""
            while True:
                c = f.read(1)
                if c == b"\x00" or not c:
                    break
                name += c
            needed.append(name.decode("utf-8", errors="replace"))

        return needed


def find_absolute_store_paths(binary_path: Path) -> list[str]:
    """Find NEEDED entries that have absolute /nix/store paths.

    Args:
        binary_path: Path to the ELF binary

    Returns:
        List of absolute /nix/store paths found in NEEDED entries
    """
    needed = _parse_elf_needed(binary_path)
    return [n for n in needed if n.startswith("/nix/store/")]


def patch_binary(
    binary_path: Path,
    absolute_paths: list[str],
    nix_store: Path,
    ld_linux_path: Path,
) -> bool:
    """Patch a binary to replace absolute store paths with library names.

    Uses patchelf (fetched via nixwrap if needed) to replace NEEDED entries.

    Args:
        binary_path: Path to the binary to patch
        absolute_paths: List of absolute /nix/store paths to replace
        nix_store: Path to the local nix store cache
        ld_linux_path: Path to ld-linux for running patchelf

    Returns:
        True if patching was successful, False otherwise
    """
    if not absolute_paths:
        return True

    # Find patchelf in the nix store
    patchelf_path = None
    for item in nix_store.iterdir():
        if "patchelf" in item.name:
            candidate = item / "bin" / "patchelf"
            if candidate.exists():
                patchelf_path = candidate
                break

    if not patchelf_path:
        return False

    # Build library path for running patchelf
    lib_paths = []
    for item in nix_store.iterdir():
        lib_dir = item / "lib"
        if lib_dir.exists():
            lib_paths.append(str(lib_dir))
    library_path = ":".join(lib_paths)

    # Make the binary writable if needed
    original_mode = binary_path.stat().st_mode
    if not os.access(binary_path, os.W_OK):
        binary_path.chmod(original_mode | 0o200)

    try:
        for abs_path in absolute_paths:
            # Extract just the library name
            lib_name = Path(abs_path).name

            # Run patchelf via ld-linux
            cmd = [
                str(ld_linux_path),
                "--library-path",
                library_path,
                str(patchelf_path),
                "--replace-needed",
                abs_path,
                lib_name,
                str(binary_path),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return False
    finally:
        # Restore original permissions
        binary_path.chmod(original_mode)

    return True


def collect_library_paths(nix_store: Path) -> list[str]:
    """Collect all library paths including nested directories.

    Some libraries (like Lua modules) are in subdirectories like lib/lua/5.1/

    Args:
        nix_store: Path to the nix store cache

    Returns:
        List of all library directories
    """
    lib_paths = []

    for item in nix_store.iterdir():
        lib_dir = item / "lib"
        if not lib_dir.exists():
            continue

        # Add the main lib directory
        lib_paths.append(str(lib_dir))

        # Also add any subdirectories that contain .so files
        for subdir in lib_dir.rglob("*"):
            if subdir.is_dir():
                # Check if this directory contains any .so files
                has_so = any(
                    f.suffix == ".so" or ".so." in f.name
                    for f in subdir.iterdir()
                    if f.is_file()
                )
                if has_so:
                    lib_paths.append(str(subdir))

    return lib_paths
