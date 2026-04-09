"""
Tests for Sphinx-Needs parser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spdx_xsafety_sbom.sphinxneeds_parser import SphinxNeedsParser


class TestSphinxNeedsParser:
    """Tests for SphinxNeedsParser class."""

    def test_parse_needs_json_file(self, fixtures_dir: Path) -> None:
        """Test parsing a Sphinx-Needs needs.json export."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        assert len(nodes) > 0
        assert "HAZ-001" in nodes
        assert "SG-001" in nodes
        assert "SSR-001" in nodes

    def test_parse_hazard_node(self, fixtures_dir: Path) -> None:
        """Test hazard node has expected fields."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        haz = nodes.get("HAZ-001")
        assert haz is not None
        assert haz.uid == "HAZ-001"
        assert haz.title == "Missing CAM message not detected"
        assert haz.node_type == "HAZ"
        assert haz.severity == "S2"
        assert haz.exposure == "E3"
        assert haz.controllability == "C2"
        assert haz.asil == "ASIL_B"

    def test_parse_parent_relationships(self, fixtures_dir: Path) -> None:
        """Test parent relationships are extracted and deduplicated."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        sg = nodes.get("SG-001")
        assert sg is not None
        assert "HAZ-001" in sg.parent_uids

        ssr = nodes.get("SSR-001")
        assert ssr is not None
        assert "SG-001" in ssr.parent_uids
        assert "TC-001" in ssr.parent_uids

    def test_build_child_relationships(self, fixtures_dir: Path) -> None:
        """Test child relationships are computed as reverse edges."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        haz = nodes.get("HAZ-001")
        assert haz is not None
        assert "SG-001" in haz.child_uids

        tc = nodes.get("TC-001")
        assert tc is not None
        assert "EVID-001" in tc.child_uids

    def test_parse_node_extracts_evidence_metadata(self, fixtures_dir: Path) -> None:
        """Test parsing captures EVID metadata fields."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        evid = nodes.get("EVID-001")
        assert evid is not None
        assert evid.evidence_artifact_id == "docs/evidence/EVID-001.txt"
        assert evid.evidence_timestamp_utc == "2025-12-12T18:02:11Z"
        assert evid.evidence_hash == "sha256:6f2b4d9f1a2b3c"

    def test_parse_document_path_and_file_refs(self, fixtures_dir: Path) -> None:
        """Test parser maps docname and file_links fields."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        ssr = nodes.get("SSR-001")
        assert ssr is not None
        assert ssr.document_path == Path("safety/ssr_doc")
        assert ssr.file_refs == ["src/cam/service.c", "src/cam/timer.c"]

    def test_parse_missing_file(self, tmp_path: Path) -> None:
        """Test error handling for missing needs.json file."""
        parser = SphinxNeedsParser(tmp_path / "missing-needs.json")

        with pytest.raises(FileNotFoundError):
            parser.parse()

    def test_parse_invalid_structure(self, tmp_path: Path) -> None:
        """Test parser rejects JSON without top-level versions key."""
        needs_path = tmp_path / "needs.json"
        needs_path.write_text('{"project": "demo"}', encoding="utf-8")

        parser = SphinxNeedsParser(needs_path)
        with pytest.raises(ValueError, match="missing top-level 'versions' key"):
            parser.parse()

    def test_parse_falls_back_to_first_version(self, tmp_path: Path) -> None:
        """Test parser uses first version when current_version is not present."""
        needs_path = tmp_path / "needs.json"
        payload = {
            "current_version": "v-missing",
            "versions": {
                "v1": {
                    "needs": {
                        "REQ-1": {
                            "id": "REQ-1",
                            "type": "req",
                            "title": "Fallback parse",
                            "content": "Parser should use first available version"
                        }
                    },
                    "needs_schema": {
                        "properties": {
                            "derived_from": {"field_type": "links"}
                        }
                    }
                }
            }
        }
        needs_path.write_text(json.dumps(payload), encoding="utf-8")

        parser = SphinxNeedsParser(needs_path)
        nodes = parser.parse()

        assert "REQ-1" in nodes
        assert nodes["REQ-1"].node_type == "REQUIREMENT"

    def test_infer_node_type_empty_type_uses_default(self) -> None:
        """Test empty type string falls back to default node type."""
        assert SphinxNeedsParser._infer_node_type("", "UNK-001") == "REQUIREMENT"
