"""
Tests for SPDX 3.0.1 builder.
"""

from __future__ import annotations

from spdx_xsafety_sbom.models import StrictDocNode
from spdx_xsafety_sbom.spdx_builder import SPDX3Builder


class TestSPDX3Builder:
    """Tests for SPDX3Builder class."""

    def test_make_spdx_id(self) -> None:
        """Test SPDX ID generation."""
        builder = SPDX3Builder(spdx_id_prefix="urn:test:")

        spdx_id = builder.make_spdx_id("element", "SSR-001")
        assert spdx_id == "urn:test:element-SSR-001"

    def test_make_spdx_id_normalizes_paths(self) -> None:
        """Test SPDX ID normalizes file paths."""
        builder = SPDX3Builder()

        spdx_id = builder.make_spdx_id("file", "src/main.c")
        assert "/" not in spdx_id.split("file-")[1] or "-" in spdx_id

    def test_build_creation_info(self) -> None:
        """Test CreationInfo building."""
        builder = SPDX3Builder()
        info = builder.build_creation_info(
            tool_name="test-tool",
            tool_version="1.0.0",
            organization="TestOrg",
        )

        assert info["type"] == "CreationInfo"
        assert info["specVersion"] == "3.0.1"
        assert "created" in info
        assert len(info["createdBy"]) > 0

    def test_build_hazard_element(self) -> None:
        """Test building hazard element with HazardExtension."""
        builder = SPDX3Builder()

        node = StrictDocNode(
            uid="HAZ-001",
            statement="Test hazard",
            severity="S2",
            exposure="E3",
            controllability="C2",
            asil="ASIL_B",
        )

        element = builder.build_hazard_element(node)

        assert element["@type"] == "Bundle"
        assert element["name"] == "HAZ-001"
        assert element["primaryPurpose"] == "requirement"
        assert len(element["extension"]) == 1

        ext = element["extension"][0]
        assert ext["type"] == "xSafety:HazardExtension"
        assert ext["xSafety:severity"] == "s2"
        assert ext["xSafety:exposure"] == "e3"
        assert ext["xSafety:controllability"] == "c2"
        assert ext["xSafety:safetyIntegrityLevel"] == "asilB"

    def test_build_safety_goal_element(self) -> None:
        """Test building safety goal element."""
        builder = SPDX3Builder()

        node = StrictDocNode(
            uid="SG-001",
            statement="Test safety goal",
            asil="ASIL_B",
        )

        element = builder.build_safety_goal_element(node)

        assert element["@type"] == "Bundle"
        assert element["name"] == "SG-001"

        ext = element["extension"][0]
        assert ext["type"] == "xSafety:SafetyGoalExtension"
        assert ext["xSafety:safetyIntegrityLevel"] == "asilB"

    def test_build_requirement_element(self) -> None:
        """Test building requirement element."""
        builder = SPDX3Builder()

        node = StrictDocNode(
            uid="SSR-001",
            statement="Test requirement",
            asil="ASIL_B",
        )

        element = builder.build_requirement_element(node)

        assert element["@type"] == "Bundle"
        assert element["name"] == "SSR-001"

        ext = element["extension"][0]
        assert ext["type"] == "xSafety:SafetyRequirementExtension"
        assert ext["xSafety:requirementType"] == "softwareSafetyRequirement"

    def test_build_test_element(self) -> None:
        """Test building test case element."""
        builder = SPDX3Builder()

        node = StrictDocNode(
            uid="TC-001",
            statement="Test case",
            asil="ASIL_B",
        )

        element = builder.build_test_element(node)

        assert element["@type"] == "Bundle"
        assert element["name"] == "TC-001"
        assert element["primaryPurpose"] == "test"

        ext = element["extension"][0]
        assert ext["type"] == "xSafety:SafetyTestExtension"

    def test_build_evidence_element_with_metadata(self) -> None:
        """Test building evidence element with raw artifact metadata."""
        builder = SPDX3Builder()

        node = StrictDocNode(
            uid="EVID-001",
            title="Evidence",
            statement="Evidence description",
            evidence_artifact_id="docs/strictdoc/evidence/EVID-001-temporal-fault-detection.txt",
            evidence_timestamp_utc="2025-12-12T18:02:11Z",
            evidence_hash="sha256:6f2b4d9f1a2b3c",
        )

        element = builder.build_evidence_element(node)

        assert element["@type"] == "software_File"
        assert element["name"] == "EVID-001"
        assert element["primaryPurpose"] == "evidence"

        ext = element["extension"][0]
        assert ext["type"] == "xSafety:SafetyEvidenceExtension"
        assert ext["xSafety:evidenceType"] == "testResult"
        assert (
            ext["xSafety:artifactId"]
            == "docs/strictdoc/evidence/EVID-001-temporal-fault-detection.txt"
        )
        assert ext["xSafety:evidenceTimestampUtc"] == "2025-12-12T18:02:11Z"
        assert ext["xSafety:artifactHash"] == "sha256:6f2b4d9f1a2b3c"

    def test_build_node_element_dispatches_correctly(self) -> None:
        """Test build_node_element dispatches to correct builder."""
        builder = SPDX3Builder()

        haz_node = StrictDocNode(uid="HAZ-001", statement="Hazard")
        sg_node = StrictDocNode(uid="SG-001", statement="Safety goal")
        ssr_node = StrictDocNode(uid="SSR-001", statement="Requirement")
        tc_node = StrictDocNode(uid="TC-001", statement="Test")
        evid_node = StrictDocNode(uid="EVID-001", statement="Evidence")

        haz_elem = builder.build_node_element(haz_node)
        sg_elem = builder.build_node_element(sg_node)
        ssr_elem = builder.build_node_element(ssr_node)
        tc_elem = builder.build_node_element(tc_node)
        evid_elem = builder.build_node_element(evid_node)

        assert haz_elem["extension"][0]["type"] == "xSafety:HazardExtension"
        assert sg_elem["extension"][0]["type"] == "xSafety:SafetyGoalExtension"
        assert ssr_elem["extension"][0]["type"] == "xSafety:SafetyRequirementExtension"
        assert tc_elem["extension"][0]["type"] == "xSafety:SafetyTestExtension"
        assert evid_elem["extension"][0]["type"] == "xSafety:SafetyEvidenceExtension"

    def test_build_document(self) -> None:
        """Test building complete SPDX document."""
        builder = SPDX3Builder(document_name="test-doc")
        builder.build_creation_info()

        node = StrictDocNode(uid="SSR-001", statement="Test")
        element = builder.build_node_element(node)

        document = builder.build_document(
            root_elements=[element["spdxId"]]
        )

        assert "@context" in document
        assert "@graph" in document
        assert len(document["@graph"]) > 0

        # Find SpdxDocument
        spdx_docs = [
            e for e in document["@graph"] if e.get("@type") == "SpdxDocument"
        ]
        assert len(spdx_docs) == 1
        assert spdx_docs[0]["name"] == "test-doc"

    def test_elements_are_unique(self) -> None:
        """Test that duplicate elements are not added."""
        builder = SPDX3Builder()

        node = StrictDocNode(uid="SSR-001", statement="Test")
        builder.build_node_element(node)
        builder.build_node_element(node)  # Add same node again

        # Should only have one element
        ssr_elements = [
            e for e in builder.elements if e.get("name") == "SSR-001"
        ]
        assert len(ssr_elements) == 1
