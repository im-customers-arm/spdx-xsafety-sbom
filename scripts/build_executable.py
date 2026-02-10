#!/usr/bin/env python3
"""
Build script for creating standalone executables.

This script automates the PyInstaller build process and handles:
- Platform detection and naming
- Version extraction from package
- Artifact organization

Usage:
    uv run python scripts/build_executable.py

Output:
    dist/spdx-xsafety-sbom-v{version}-{platform}-{arch}[.exe]
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def get_version() -> str:
    """Extract version from package __init__.py."""
    init_file = get_project_root() / "src" / "spdx_xsafety_sbom" / "__init__.py"
    version = "0.1.0"  # fallback
    
    if init_file.exists():
        for line in init_file.read_text().splitlines():
            if line.startswith("__version__"):
                version = line.split("=")[1].strip().strip('"').strip("'")
                break
    
    return version


def get_platform_info() -> tuple[str, str]:
    """
    Get platform and architecture info for naming.
    
    Returns:
        Tuple of (platform_name, architecture).
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Normalize platform name
    platform_map = {
        "darwin": "macos",
        "windows": "windows",
        "linux": "linux",
    }
    platform_name = platform_map.get(system, system)
    
    # Normalize architecture
    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "i386": "x86",
        "i686": "x86",
    }
    arch = arch_map.get(machine, machine)
    
    return platform_name, arch


def get_executable_name(version: str, platform_name: str, arch: str) -> str:
    """
    Generate the executable name with version and platform info.
    
    Args:
        version: Package version string.
        platform_name: Normalized platform name.
        arch: Normalized architecture.
    
    Returns:
        Executable filename.
    """
    base_name = f"spdx-xsafety-sbom-v{version}-{platform_name}-{arch}"
    
    if platform_name == "windows":
        return f"{base_name}.exe"
    
    return base_name


def build_executable() -> int:
    """
    Build the executable using PyInstaller.
    
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    project_root = get_project_root()
    spec_file = project_root / "scripts" / "spdx-xsafety-sbom.spec"
    dist_dir = project_root / "dist"
    
    # Ensure spec file exists
    if not spec_file.exists():
        print(f"Error: Spec file not found: {spec_file}")
        return 1
    
    # Get version and platform info
    version = get_version()
    platform_name, arch = get_platform_info()
    final_name = get_executable_name(version, platform_name, arch)
    
    print(f"Building spdx-xsafety-sbom v{version} for {platform_name}-{arch}")
    print(f"Output: {final_name}")
    print("-" * 60)
    
    # Run PyInstaller
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_file),
    ]
    
    result = subprocess.run(cmd, cwd=project_root)
    
    if result.returncode != 0:
        print(f"Error: PyInstaller failed with exit code {result.returncode}")
        return result.returncode
    
    # Rename output to include version and platform
    original_name = "spdx-xsafety-sbom"
    if platform_name == "windows":
        original_name += ".exe"
    
    original_path = dist_dir / original_name
    final_path = dist_dir / final_name
    
    if original_path.exists():
        # Remove existing file if present
        if final_path.exists():
            final_path.unlink()
        
        shutil.move(original_path, final_path)
        print("-" * 60)
        print(f"Success! Executable created: {final_path}")
        print(f"Size: {final_path.stat().st_size / (1024 * 1024):.1f} MB")
    else:
        print(f"Warning: Expected output not found at {original_path}")
        return 1
    
    return 0


def main() -> None:
    """Main entry point."""
    sys.exit(build_executable())


if __name__ == "__main__":
    main()
