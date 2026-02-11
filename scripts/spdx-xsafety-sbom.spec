# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for spdx-xsafety-sbom.

This builds a standalone executable that bundles:
- The CLI entry point (cli:main)
- All runtime dependencies (strictdoc, click, rich, pydantic)
- Data files (SHACL shapes, JSON-LD contexts)
- Optional validation dependencies (pyshacl, rdflib)

Usage:
    pyinstaller scripts/spdx-xsafety-sbom.spec

Output:
    dist/spdx-xsafety-sbom (or .exe on Windows)
"""

import sys
from pathlib import Path

# Determine project root
SPEC_DIR = Path(SPECPATH)
PROJECT_ROOT = SPEC_DIR.parent

# Read version from package
version = "0.1.0"
try:
    init_file = PROJECT_ROOT / "src" / "spdx_xsafety_sbom" / "__init__.py"
    if init_file.exists():
        for line in init_file.read_text().splitlines():
            if line.startswith("__version__"):
                version = line.split("=")[1].strip().strip('"').strip("'")
                break
except Exception:
    pass

# Platform-specific executable name
exe_name = "spdx-xsafety-sbom"
if sys.platform == "win32":
    exe_name += ".exe"

# Data files to bundle
datas = [
    # SHACL shapes for validation
    (str(PROJECT_ROOT / "spdx_extensions" / "shacl"), "spdx_extensions/shacl"),
    # JSON-LD contexts
    (str(PROJECT_ROOT / "spdx_extensions" / "contexts"), "spdx_extensions/contexts"),
]

# Hidden imports that PyInstaller may miss
hidden_imports = [
    # Click and Rich
    "click",
    "rich",
    "rich.console",
    "rich.table",
    "rich.progress",
    "rich.markup",
    # Pydantic
    "pydantic",
    "pydantic.fields",
    "pydantic_core",
    # StrictDoc dependencies
    "strictdoc",
    "tree_sitter",
    "tree_sitter_languages",
    "lxml",
    "lxml.etree",
    "jinja2",
    "docutils",
    "beautifulsoup4",
    "bs4",
    # Validation (optional but bundle if available)
    "pyshacl",
    "rdflib",
    "rdflib.plugins",
    "rdflib.plugins.parsers",
    "rdflib.plugins.serializers",
    "pyld",
    "jsonschema",
    # Standard library that may need explicit inclusion
    "json",
    "pathlib",
    "logging",
    "typing",
]

# Collect all submodules for complex packages
collect_submodules = [
    "strictdoc",
    "rdflib",
    "pyshacl",
    "pydantic",
    "rich",
]

# Build the Analysis
a = Analysis(
    [str(PROJECT_ROOT / "src" / "spdx_xsafety_sbom" / "cli.py")],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude test/dev dependencies
        "pytest",
        "pytest_cov",
        "mypy",
        "ruff",
        # Exclude unused stdlib
        "tkinter",
        "unittest",
    ],
    noarchive=False,
    optimize=0,
)

# Collect submodules
for pkg in collect_submodules:
    try:
        from PyInstaller.utils.hooks import collect_submodules as cs
        a.hiddenimports.extend(cs(pkg))
    except Exception:
        pass

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=exe_name.replace(".exe", ""),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
