"""
Pytest configuration and fixtures for spdx-xsafety-sbom tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_strictdoc_export(fixtures_dir: Path) -> Path:
    """Path to sample StrictDoc .sdoc directory."""
    return fixtures_dir / "sdoc"


@pytest.fixture
def sample_sphinxneeds_export(fixtures_dir: Path) -> Path:
    """Path to sample Sphinx-Needs needs.json export."""
    return fixtures_dir / "sphinxneeds" / "needs.json"


@pytest.fixture
def sample_source_dir(fixtures_dir: Path) -> Path:
    """Path to sample source files with requirement markers."""
    return fixtures_dir / "source"


@pytest.fixture
def sample_sbom(fixtures_dir: Path) -> dict[str, Any]:
    """Load sample SBOM document."""
    sbom_path = fixtures_dir / "sample-sbom.json"
    with open(sbom_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    """Temporary output path for generated files."""
    return tmp_path / "output.json"


@pytest.fixture
def strictdoc_nodes() -> dict[str, Any]:
    """Sample parsed StrictDoc nodes for testing."""
    return {
        "HAZ-001": {
            "uid": "HAZ-001",
            "title": "Missing CAM message not detected",
            "statement": "Missing CAM message not detected within timeout period",
            "severity": "S2",
            "exposure": "E3",
            "controllability": "C2",
            "asil": "ASIL_B",
            "parent_uids": [],
        },
        "SG-001": {
            "uid": "SG-001",
            "title": "CAM message timeout detection",
            "statement": "Ensure CAM message reception is monitored with timeout detection",
            "asil": "ASIL_B",
            "parent_uids": ["HAZ-001"],
        },
        "SSR-001": {
            "uid": "SSR-001",
            "title": "Timer scheduling",
            "statement": "cam-service shall schedule a per-event timer that triggers a safety violation if the next event is not received within 1000ms",
            "asil": "ASIL_B",
            "parent_uids": ["SG-001"],
        },
        "TC-001": {
            "uid": "TC-001",
            "title": "Test timer trigger",
            "statement": "Verify timer triggers on missing CAM message",
            "asil": "ASIL_B",
            "parent_uids": ["SSR-001"],
        },
    }
