"""
Tests for StrictDoc parser.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spdx_xsafety_sbom.strictdoc_parser import StrictDocParser, parse_strictdoc_export


class TestStrictDocParser:
    """Tests for StrictDocParser class."""

    def test_parse_export_directory(self, fixtures_dir: Path) -> None:
        """Test parsing a StrictDoc .sdoc directory."""
        export_path = fixtures_dir / "sdoc"
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        assert len(nodes) > 0
        assert "HAZ-001" in nodes
        assert "SG-001" in nodes
        assert "SSR-001" in nodes

    def test_parse_hazard_node(self, fixtures_dir: Path) -> None:
        """Test hazard node has correct data."""
        export_path = fixtures_dir / "sdoc"
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        haz = nodes.get("HAZ-001")
        assert haz is not None
        assert haz.uid == "HAZ-001"
        assert haz.title == "Missing CAM message not detected"

    def test_parse_parent_relationships(self, fixtures_dir: Path) -> None:
        """Test parent-child relationships are extracted."""
        export_path = fixtures_dir / "sdoc"
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        sg = nodes.get("SG-001")
        assert sg is not None
        assert "HAZ-001" in sg.parent_uids

        ssr = nodes.get("SSR-001")
        assert ssr is not None
        assert "SG-001" in ssr.parent_uids

    def test_build_child_relationships(self, fixtures_dir: Path) -> None:
        """Test child relationships are computed."""
        export_path = fixtures_dir / "sdoc"
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        haz = nodes.get("HAZ-001")
        assert haz is not None
        assert "SG-001" in haz.child_uids

    def test_get_requirement_type(self, fixtures_dir: Path) -> None:
        """Test requirement type inference from UID."""
        export_path = fixtures_dir / "sdoc"
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        assert nodes["HAZ-001"].get_requirement_type() == "HAZ"
        assert nodes["SG-001"].get_requirement_type() == "SG"
        assert nodes["SSR-001"].get_requirement_type() == "SSR"

    def test_parse_missing_directory(self, tmp_path: Path) -> None:
        """Test error handling for missing directory."""
        parser = StrictDocParser(tmp_path / "nonexistent")

        with pytest.raises(FileNotFoundError):
            parser.parse()

    def test_convenience_function(self, fixtures_dir: Path) -> None:
        """Test parse_strictdoc_export convenience function."""
        export_path = fixtures_dir / "sdoc"
        nodes = parse_strictdoc_export(export_path)

        assert len(nodes) > 0
        assert "HAZ-001" in nodes

    def test_parse_json_node_extracts_evidence_metadata(self, tmp_path: Path) -> None:
        """Test JSON parsing captures EVID metadata fields."""
        parser = StrictDocParser(tmp_path)

        parser._parse_json_node(
            {
                "UID": "EVID-001",
                "NODE_TYPE": "EVIDENCE",
                "TITLE": "Temporal fault evidence",
                "STATEMENT": "Logs for temporal fault case",
                "ARTIFACT_ID": "docs/strictdoc/evidence/EVID-001-temporal-fault-detection.txt",
                "TIMESTAMP_UTC": "2025-12-12T18:02:11Z",
                "HASH": "sha256:6f2b4d9f1a2b3c",
                "RELATIONS": [{"TYPE": "Parent", "VALUE": "TC-001"}],
            }
        )

        evid = parser._nodes.get("EVID-001")
        assert evid is not None
        assert (
            evid.evidence_artifact_id
            == "docs/strictdoc/evidence/EVID-001-temporal-fault-detection.txt"
        )
        assert evid.evidence_timestamp_utc == "2025-12-12T18:02:11Z"
        assert evid.evidence_hash == "sha256:6f2b4d9f1a2b3c"
