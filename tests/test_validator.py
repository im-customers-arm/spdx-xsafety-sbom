"""
Tests for SPDX validator.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from spdx_xsafety_sbom.validation import validate_sbom, validate_structure


class TestValidateStructure:
    """Tests for structure validation."""

    def test_valid_document(self, sample_sbom: dict[str, Any]) -> None:
        """Test validation of valid SBOM."""
        result = validate_structure(sample_sbom)

        assert result.valid or len(result.errors) == 0
        assert "element_count" in result.info
        assert "relationship_count" in result.info

    def test_missing_context(self) -> None:
        """Test validation catches missing @context."""
        document = {"@graph": []}
        result = validate_structure(document)

        assert "Missing @context" in result.errors

    def test_missing_graph(self) -> None:
        """Test validation catches missing @graph."""
        document = {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        result = validate_structure(document)

        assert "Missing @graph" in result.errors

    def test_empty_graph(self) -> None:
        """Test validation catches empty @graph."""
        document = {
            "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
            "@graph": [],
        }
        result = validate_structure(document)

        assert "@graph is empty" in result.errors

    def test_missing_spdx_document(self) -> None:
        """Test validation catches missing SpdxDocument."""
        document = {
            "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
            "@graph": [
                {"@type": "Bundle", "spdxId": "urn:test:1", "name": "Test"}
            ],
        }
        result = validate_structure(document)

        assert "No SpdxDocument element found" in result.errors

    def test_duplicate_spdx_id(self) -> None:
        """Test validation catches duplicate spdxId."""
        document = {
            "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
            "@graph": [
                {"@type": "Bundle", "spdxId": "urn:test:1", "name": "Test1"},
                {"@type": "Bundle", "spdxId": "urn:test:1", "name": "Test2"},
            ],
        }
        result = validate_structure(document)

        assert any("Duplicate spdxId" in e for e in result.errors)

    def test_evidence_extension_metadata_type_validation(self) -> None:
        """Test evidence metadata fields must be strings when present."""
        document = {
            "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
            "@graph": [
                {
                    "@type": "SpdxDocument",
                    "spdxId": "urn:test:document",
                    "name": "doc",
                    "specVersion": "3.0.1",
                    "creationInfo": {"created": "2026-02-06T00:00:00Z", "createdBy": []},
                },
                {
                    "@type": "software_File",
                    "spdxId": "urn:test:evidence-EVID-001",
                    "name": "EVID-001",
                    "extension": [
                        {
                            "type": "xSafety:SafetyEvidenceExtension",
                            "xSafety:evidenceType": "testResult",
                            "xSafety:artifactId": 123,
                        }
                    ],
                },
            ],
        }
        result = validate_structure(document)
        assert any("non-string artifactId" in e for e in result.errors)


class TestValidateSbom:
    """Tests for full SBOM validation."""

    def test_validate_existing_file(self, fixtures_dir: Path) -> None:
        """Test validation of existing SBOM file."""
        sbom_path = fixtures_dir / "sample-sbom.json"
        result = validate_sbom(sbom_path)

        # Should be valid or have only warnings
        assert result.valid or len(result.errors) == 0

    def test_validate_missing_file(self, tmp_path: Path) -> None:
        """Test validation of missing file."""
        result = validate_sbom(tmp_path / "nonexistent.json")

        assert not result.valid
        assert any("not found" in e for e in result.errors)

    def test_validate_invalid_json(self, tmp_path: Path) -> None:
        """Test validation of invalid JSON."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        result = validate_sbom(invalid_file)

        assert not result.valid
        assert any("Invalid JSON" in e for e in result.errors)
