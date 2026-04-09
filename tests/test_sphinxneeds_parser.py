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
        assert "FSC-001" in nodes
        assert "TSR-001" in nodes
        assert "SSR-001" in nodes
        assert "SWA-001" in nodes

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

        fsc = nodes.get("FSC-001")
        assert fsc is not None
        assert "SG-001" in fsc.parent_uids

        tsr = nodes.get("TSR-001")
        assert tsr is not None
        assert "FSC-001" in tsr.parent_uids

        ssr = nodes.get("SSR-001")
        assert ssr is not None
        assert "TSR-001" in ssr.parent_uids
        assert "TC-001" in ssr.parent_uids

    def test_build_child_relationships(self, fixtures_dir: Path) -> None:
        """Test child relationships are computed as reverse edges."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        haz = nodes.get("HAZ-001")
        assert haz is not None
        assert "SG-001" in haz.child_uids

        sg = nodes.get("SG-001")
        assert sg is not None
        assert "FSC-001" in sg.child_uids

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

    def test_docname_resolves_to_rst_fixture(self, fixtures_dir: Path) -> None:
        """Test parsed docname can be resolved to an .rst file in the fixture tree."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        ssr = nodes.get("SSR-001")
        assert ssr is not None
        assert ssr.document_path is not None

        rst_path = export_path.parent / Path(f"{ssr.document_path}.rst")
        assert rst_path.exists()
        rst_text = rst_path.read_text(encoding="utf-8")
        assert ":id: SSR-001" in rst_text

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

    def test_parse_empty_needs_dict(self, tmp_path: Path) -> None:
        """Test parser returns an empty result when the selected version has no needs."""
        needs_path = tmp_path / "needs.json"
        needs_path.write_text(
            json.dumps(
                {
                    "current_version": "v1",
                    "versions": {"v1": {"needs": {}, "needs_schema": {"properties": {}}}},
                }
            ),
            encoding="utf-8",
        )

        parser = SphinxNeedsParser(needs_path)
        assert parser.parse() == {}

    def test_parse_duplicate_id_skipped(self, tmp_path: Path) -> None:
        """Test parser keeps the first node when duplicate need ids appear."""
        needs_path = tmp_path / "needs.json"
        needs_path.write_text(
            json.dumps(
                {
                    "current_version": "v1",
                    "versions": {
                        "v1": {
                            "needs": {
                                "FIRST": {
                                    "id": "REQ-1",
                                    "type": "req",
                                    "title": "First copy",
                                    "content": "first",
                                },
                                "SECOND": {
                                    "id": "REQ-1",
                                    "type": "req",
                                    "title": "Second copy",
                                    "content": "second",
                                },
                            },
                            "needs_schema": {"properties": {}},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        parser = SphinxNeedsParser(needs_path)
        nodes = parser.parse()

        assert list(nodes) == ["REQ-1"]
        assert nodes["REQ-1"].title == "First copy"

    def test_schema_backlinks_excluded_from_parent_uids(self, fixtures_dir: Path) -> None:
        """Test schema-declared backlink fields do not become parent_uids."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        # HAZ-001 has links: [SG-001] and derived_from_back: [SG-001].
        # backlinks (derived_from_back) must be excluded, leaving only the SG-001
        # from the forward 'links' field.
        haz = nodes["HAZ-001"]
        assert haz.parent_uids == ["SG-001"]

    def test_content_fallback_to_description(self, fixtures_dir: Path) -> None:
        """Test statement falls back to description when content is absent."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        assert nodes["SSR-001"].statement == "cam-service shall schedule a per-event timer"

    def test_parse_fsc_node_type(self, fixtures_dir: Path) -> None:
        """Test FSC (Functional Safety Concept) type is correctly mapped from 'fsc' type string."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        fsc = nodes.get("FSC-001")
        assert fsc is not None
        assert fsc.node_type == "FSC"
        assert fsc.asil == "ASIL_B"
        assert fsc.document_path == Path("safety/fsc_doc")

    def test_parse_tsr_node_type(self, fixtures_dir: Path) -> None:
        """Test TSR (Technical Safety Requirement) type is correctly parsed."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        tsr = nodes.get("TSR-001")
        assert tsr is not None
        assert tsr.node_type == "TSR"
        assert tsr.asil == "ASIL_B"

    def test_parse_swa_with_realises_link(self, fixtures_dir: Path) -> None:
        """Test SWA node with a realises forward link maps to parent_uids."""
        export_path = fixtures_dir / "sphinxneeds" / "needs.json"
        parser = SphinxNeedsParser(export_path)
        nodes = parser.parse()

        swa = nodes.get("SWA-001")
        assert swa is not None
        assert swa.node_type == "SWA"
        assert "SSR-001" in swa.parent_uids

    def test_parse_infer_fsc_type_from_uid_prefix(self) -> None:
        """Test _TYPE_MAP resolves 'fsc' type string to FSC (not UID inference)."""
        assert SphinxNeedsParser._infer_node_type("fsc", "FSC-001") == "FSC"

    def test_parse_infer_tsc_type_from_uid_prefix(self) -> None:
        """Test _TYPE_MAP resolves 'tsc' type string to TSC."""
        assert SphinxNeedsParser._infer_node_type("tsc", "TSC-001") == "TSC"
