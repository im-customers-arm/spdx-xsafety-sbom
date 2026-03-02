"""
Path utilities for frozen (PyInstaller) and development environments.

This module provides functions to resolve paths correctly whether
the code is running from source or from a PyInstaller bundle.
"""

from __future__ import annotations

import sys
from pathlib import Path


def get_bundle_dir() -> Path:
    """
    Get the directory containing bundled data files.

    Returns:
        Path to bundle directory (PyInstaller temp dir or project root).
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # Running from PyInstaller bundle
        return Path(sys._MEIPASS)
    else:
        # Running from source - go up from src/spdx_xsafety_sbom/
        return Path(__file__).resolve().parent.parent.parent


def get_spdx_extensions_dir() -> Path:
    """
    Get the path to spdx_extensions directory.

    Returns:
        Path to spdx_extensions directory.
    """
    return get_bundle_dir() / "spdx_extensions"


def get_shacl_shapes_path() -> Path:
    """
    Get the path to the SHACL shapes file.

    Returns:
        Path to safety-shapes.ttl file.
    """
    return get_spdx_extensions_dir() / "shacl" / "safety-shapes.ttl"


def get_jsonld_context_path() -> Path:
    """
    Get the path to the JSON-LD context file.

    Returns:
        Path to safety-context.jsonld file.
    """
    return get_spdx_extensions_dir() / "contexts" / "safety-context.jsonld"


def is_frozen() -> bool:
    """
    Check if running from a frozen (PyInstaller) bundle.

    Returns:
        True if running from PyInstaller bundle, False otherwise.
    """
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
