"""
Tests for generator module.
"""

from __future__ import annotations

import json
from pathlib import Path

from spdx_xsafety_sbom.generator import generate_design_sbom


class TestGenerateDesignSbom:
    """Tests for generate_design_sbom function."""

    def test_generate_from_strictdoc_export(
        self, fixtures_dir: Path, tmp_output: Path
    ) -> None:
        """Test generating SBOM from StrictDoc .sdoc files."""
        export_path = fixtures_dir / "sdoc"

        result = generate_design_sbom(
            strictdoc_export_path=export_path,
            output_path=tmp_output,
            scan_source_markers=False,
            validate_output=True,
        )

        assert result.success
        assert result.output_path == tmp_output
        assert result.element_count > 0
        assert tmp_output.exists()

        # Verify output is valid JSON
        with open(tmp_output) as f:
            document = json.load(f)

        assert "@context" in document
        assert "@graph" in document

    def test_generate_with_source_scanning(
        self, fixtures_dir: Path, tmp_output: Path
    ) -> None:
        """Test generating SBOM with source code scanning."""
        export_path = fixtures_dir / "sdoc"
        source_path = fixtures_dir / "source"

        result = generate_design_sbom(
            strictdoc_export_path=export_path,
            output_path=tmp_output,
            source_root=source_path,
            scan_source_markers=True,
            validate_output=True,
        )

        assert result.success
        assert result.relationship_count > 0

        # Check for testedOn relationships
        with open(tmp_output) as f:
            document = json.load(f)

        relationships = [
            e for e in document["@graph"] if e.get("@type") == "Relationship"
        ]
        tested_on_rels = [
            r for r in relationships if r.get("relationshipType") == "testedOn"
        ]
        assert len(tested_on_rels) > 0

    def test_generate_creates_output_directory(
        self, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """Test that output directory is created if missing."""
        export_path = fixtures_dir / "sdoc"
        output_path = tmp_path / "subdir" / "nested" / "output.json"

        result = generate_design_sbom(
            strictdoc_export_path=export_path,
            output_path=output_path,
            scan_source_markers=False,
        )

        assert result.success
        assert output_path.exists()
        assert output_path.parent.exists()

    def test_generate_with_custom_prefix(
        self, fixtures_dir: Path, tmp_output: Path
    ) -> None:
        """Test generating SBOM with custom SPDX ID prefix."""
        export_path = fixtures_dir / "sdoc"

        result = generate_design_sbom(
            strictdoc_export_path=export_path,
            output_path=tmp_output,
            spdx_id_prefix="urn:custom:prefix:",
            scan_source_markers=False,
        )

        assert result.success

        with open(tmp_output) as f:
            document = json.load(f)

        # Check that elements use custom prefix
        for elem in document["@graph"]:
            spdx_id = elem.get("spdxId", "")
            if spdx_id:
                assert spdx_id.startswith("urn:custom:prefix:")

    def test_generate_missing_export_path(self, tmp_path: Path) -> None:
        """Test error handling for missing export path."""
        result = generate_design_sbom(
            strictdoc_export_path=tmp_path / "nonexistent",
            output_path=tmp_path / "output.json",
        )

        assert not result.success
        assert len(result.errors) > 0

    def test_generate_empty_export(self, tmp_path: Path) -> None:
        """Test handling of empty export directory."""
        empty_dir = tmp_path / "empty-export"
        empty_dir.mkdir()

        result = generate_design_sbom(
            strictdoc_export_path=empty_dir,
            output_path=tmp_path / "output.json",
        )

        assert not result.success
        assert any("No requirements found" in e for e in result.errors)

    def test_result_includes_timing(
        self, fixtures_dir: Path, tmp_output: Path
    ) -> None:
        """Test that result includes generation time."""
        export_path = fixtures_dir / "sdoc"

        result = generate_design_sbom(
            strictdoc_export_path=export_path,
            output_path=tmp_output,
            scan_source_markers=False,
        )

        assert result.success
        assert result.generation_time >= 0  # Can be 0.0 if generation is very fast
        assert result.timestamp is not None
