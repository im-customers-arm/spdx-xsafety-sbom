"""
Tests for generator module.
"""

from __future__ import annotations

import json
from pathlib import Path

from spdx_xsafety_sbom.generator import (
    _detect_input_format,
    generate_design_sbom,
    generate_from_config,
)
from spdx_xsafety_sbom.models import GeneratorConfig


def _extract_graph_elements_by_name(
    document: dict[str, object],
) -> tuple[dict[str, dict[str, object]], set[tuple[str, str, str]]]:
    """Extract stable element and relationship views from a generated graph."""
    graph = document["@graph"]
    id_to_name = {
        element["spdxId"]: element["name"]
        for element in graph
        if isinstance(element, dict)
        and element.get("@type") not in {"Relationship", "SpdxDocument"}
    }
    elements_by_name = {
        element["name"]: {
            "type": element.get("@type"),
            "primaryPurpose": element.get("primaryPurpose"),
        }
        for element in graph
        if isinstance(element, dict)
        and element.get("name")
        and element.get("@type") not in {"Relationship", "SpdxDocument"}
    }
    relationships = {
        (
            relationship.get("relationshipType"),
            id_to_name.get(relationship.get("from")),
            id_to_name.get(target),
        )
        for relationship in graph
        if isinstance(relationship, dict) and relationship.get("@type") == "Relationship"
        for target in relationship.get("to", [])
        if id_to_name.get(relationship.get("from")) and id_to_name.get(target)
    }
    return elements_by_name, relationships


class TestGenerateDesignSbom:
    """Tests for generate_design_sbom function."""

    def test_generate_from_strictdoc_export(self, fixtures_dir: Path, tmp_output: Path) -> None:
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

    def test_generate_with_source_scanning(self, fixtures_dir: Path, tmp_output: Path) -> None:
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

        relationships = [e for e in document["@graph"] if e.get("@type") == "Relationship"]
        tested_on_rels = [r for r in relationships if r.get("relationshipType") == "testedOn"]
        assert len(tested_on_rels) > 0

    def test_generate_creates_output_directory(self, fixtures_dir: Path, tmp_path: Path) -> None:
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

    def test_generate_with_custom_prefix(self, fixtures_dir: Path, tmp_output: Path) -> None:
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

    def test_result_includes_timing(self, fixtures_dir: Path, tmp_output: Path) -> None:
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

    def test_generate_from_sphinxneeds_export(
        self, sample_sphinxneeds_export: Path, tmp_output: Path
    ) -> None:
        """Test generating an SBOM from a Sphinx-Needs needs.json export."""
        result = generate_design_sbom(
            strictdoc_export_path=sample_sphinxneeds_export,
            output_path=tmp_output,
            scan_source_markers=False,
            validate_output=True,
        )

        assert result.success
        assert result.output_path == tmp_output
        assert result.element_count > 0
        assert tmp_output.exists()

    def test_generate_from_sphinxneeds_with_need_markers(
        self, sample_sphinxneeds_export: Path, tmp_path: Path, tmp_output: Path
    ) -> None:
        """Test generating from Sphinx-Needs input with @need marker scanning."""
        source_root = tmp_path / "source"
        source_root.mkdir()
        (source_root / "cam_service_need.c").write_text(
            "// @need[SSR-001]\nvoid schedule_timeout_timer(void) {\n    trigger_alarm();\n}\n",
            encoding="utf-8",
        )

        result = generate_design_sbom(
            strictdoc_export_path=sample_sphinxneeds_export,
            output_path=tmp_output,
            source_root=source_root,
            scan_source_markers=True,
            validate_output=True,
            input_format="sphinx-needs",
        )

        assert result.success

        with open(tmp_output, encoding="utf-8") as f:
            document = json.load(f)

        relationships = [e for e in document["@graph"] if e.get("@type") == "Relationship"]
        tested_on_rels = [r for r in relationships if r.get("relationshipType") == "testedOn"]
        assert tested_on_rels

    def test_detect_input_format(self, fixtures_dir: Path, sample_sphinxneeds_export: Path) -> None:
        """Test input format auto-detection for both supported formats."""
        assert _detect_input_format(fixtures_dir / "sdoc") == "strictdoc"
        assert _detect_input_format(sample_sphinxneeds_export) == "sphinx-needs"

    def test_generate_from_config_with_input_path(
        self, sample_sphinxneeds_export: Path, tmp_output: Path
    ) -> None:
        """Test generation from GeneratorConfig using the new input_path field."""
        config = GeneratorConfig(
            input_path=sample_sphinxneeds_export,
            input_format="sphinx-needs",
            output_path=tmp_output,
            scan_source_markers=False,
            validate_output=True,
        )

        result = generate_from_config(config)

        assert result.success
        assert result.output_path == tmp_output

    def test_generator_config_accepts_strictdoc_export_path_alias(
        self, sample_strictdoc_export: Path, tmp_output: Path
    ) -> None:
        """Test GeneratorConfig backward compatibility via strictdoc_export_path alias."""
        config = GeneratorConfig(
            strictdoc_export_path=sample_strictdoc_export,
            output_path=tmp_output,
        )

        assert config.input_path == sample_strictdoc_export
        assert config.input_format == "auto"

    def test_generate_golden_output_parity_for_common_requirements(
        self, fixtures_dir: Path, tmp_path: Path
    ) -> None:
        """Test StrictDoc and Sphinx-Needs generation agree on the shared semantic subset."""
        strictdoc_output = tmp_path / "strictdoc.json"
        sphinxneeds_output = tmp_path / "sphinxneeds.json"

        strictdoc_result = generate_design_sbom(
            strictdoc_export_path=fixtures_dir / "sdoc",
            output_path=strictdoc_output,
            scan_source_markers=False,
            validate_output=False,
            input_format="strictdoc",
        )
        sphinxneeds_result = generate_design_sbom(
            strictdoc_export_path=fixtures_dir / "sphinxneeds" / "needs.json",
            output_path=sphinxneeds_output,
            scan_source_markers=False,
            validate_output=False,
            input_format="sphinx-needs",
        )

        assert strictdoc_result.success
        assert sphinxneeds_result.success

        with open(strictdoc_output, encoding="utf-8") as f:
            strictdoc_document = json.load(f)
        with open(sphinxneeds_output, encoding="utf-8") as f:
            sphinxneeds_document = json.load(f)

        strictdoc_elements, strictdoc_relationships = _extract_graph_elements_by_name(
            strictdoc_document
        )
        sphinxneeds_elements, sphinxneeds_relationships = _extract_graph_elements_by_name(
            sphinxneeds_document
        )

        shared_names = {"HAZ-001", "SG-001", "SSR-001", "TC-001", "EVID-001"}
        expected_relationships = {
            ("descendantOf", "SG-001", "HAZ-001"),
            ("descendantOf", "TC-001", "SSR-001"),
            ("descendantOf", "EVID-001", "TC-001"),
            ("hasTestCase", "SSR-001", "TC-001"),
            ("hasEvidence", "TC-001", "EVID-001"),
        }

        assert {name: strictdoc_elements[name] for name in shared_names} == {
            name: sphinxneeds_elements[name] for name in shared_names
        }
        assert expected_relationships <= strictdoc_relationships
        assert expected_relationships <= sphinxneeds_relationships
