"""
SPDX 3.0.1 Element and Extension builder.

This module constructs SPDX 3.0.1 JSON-LD elements with xSafety extensions:
- Bundle elements for requirements, tests, evidence
- software_Package for components
- software_File for source files
- Extension attachments for safety metadata
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom.constants import (
    ASIL_LEVELS,
    CONTROLLABILITY_LEVELS,
    EVIDENCE_TYPES,
    EXPOSURE_LEVELS,
    REQUIREMENT_TYPES,
    SEVERITY_LEVELS,
    SPDX_CONTEXT,
    SPDX_VERSION,
    TEST_TYPES,
    XSAFETY_NS,
)
from spdx_xsafety_sbom.models import RangeLink, StrictDocNode

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class SPDX3Builder:
    """Builder for SPDX 3.0.1 elements with xSafety extensions."""

    def __init__(
        self,
        spdx_id_prefix: str = "urn:spdx:example:",
        document_name: str = "design-sbom",
    ) -> None:
        """
        Initialize the SPDX builder.

        Args:
            spdx_id_prefix: Prefix for SPDX element IDs.
            document_name: Name for the SPDX document.
        """
        self.spdx_id_prefix = spdx_id_prefix
        self.document_name = document_name
        self._elements: list[dict[str, Any]] = []
        self._element_ids: set[str] = set()
        self._creation_info: dict[str, Any] | None = None

    def make_spdx_id(self, element_type: str, identifier: str) -> str:
        """
        Generate a unique SPDX ID.

        Args:
            element_type: Type prefix (element, relationship, file, etc.)
            identifier: Unique identifier within the type.

        Returns:
            Full SPDX ID string.
        """
        # Normalize identifier (replace special chars)
        safe_id = identifier.replace("/", "-").replace("\\", "-").replace(" ", "-")
        return f"{self.spdx_id_prefix}{element_type}-{safe_id}"

    def build_creation_info(
        self,
        tool_name: str = "spdx-xsafety-sbom",
        tool_version: str = "0.1.0",
        organization: str | None = None,
    ) -> dict[str, Any]:
        """
        Build CreationInfo object.

        Args:
            tool_name: Name of the generating tool.
            tool_version: Version of the tool.
            organization: Optional organization name.

        Returns:
            CreationInfo dictionary.
        """
        creators = [
            {
                "type": "Tool",
                "spdxId": self.make_spdx_id("tool", tool_name),
                "name": tool_name,
                "description": f"SPDX 3.0.1 Design SBOM Generator v{tool_version}",
            }
        ]

        if organization:
            creators.append(
                {
                    "type": "Organization",
                    "spdxId": self.make_spdx_id("org", organization.lower().replace(" ", "-")),
                    "name": organization,
                }
            )

        self._creation_info = {
            "type": "CreationInfo",
            "specVersion": SPDX_VERSION,
            "created": datetime.now(timezone.utc).isoformat(),
            "createdBy": [c["spdxId"] for c in creators],
            "createdUsing": [creators[0]["spdxId"]],
        }

        # Add creator elements
        for creator in creators:
            self._add_element(creator)

        return self._creation_info

    def build_document(
        self,
        namespace: str | None = None,
        root_elements: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Build the SpdxDocument root element.

        Args:
            namespace: Optional namespace URI.
            root_elements: List of root element SPDX IDs.

        Returns:
            Complete SPDX 3.0.1 JSON-LD document.
        """
        if self._creation_info is None:
            self.build_creation_info()

        doc_id = self.make_spdx_id("document", self.document_name)

        # Build namespace map for xSafety extension
        namespace_map = [
            {
                "prefix": "xSafety",
                "namespace": XSAFETY_NS,
            }
        ]

        # SpdxDocument element
        spdx_document = {
            "@type": "SpdxDocument",
            "spdxId": doc_id,
            "name": self.document_name,
            "specVersion": SPDX_VERSION,
            "creationInfo": self._creation_info,
            "namespaceMap": namespace_map,
            "rootElement": root_elements or [],
            "element": list(self._element_ids - {doc_id}),
        }

        # Build complete JSON-LD document
        document = {
            "@context": [
                SPDX_CONTEXT,
                {"xSafety": XSAFETY_NS},
            ],
            "@graph": [spdx_document] + self._elements,
        }

        return document

    def _add_element(self, element: dict[str, Any]) -> str:
        """
        Add an element to the graph.

        Args:
            element: SPDX element dictionary.

        Returns:
            SPDX ID of the element.
        """
        spdx_id = element.get("spdxId")
        if spdx_id and spdx_id not in self._element_ids:
            self._elements.append(element)
            self._element_ids.add(spdx_id)
        return spdx_id

    # =========================================================================
    # Requirement Elements
    # =========================================================================

    def build_hazard_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build a Bundle element for a hazard (HAZ-*) with HazardExtension.

        Args:
            node: StrictDoc hazard node.

        Returns:
            SPDX Bundle element.
        """
        spdx_id = self.make_spdx_id("element", node.uid)

        # Build HazardExtension
        extension = {
            "type": "xSafety:HazardExtension",
        }

        if node.severity:
            extension["xSafety:severity"] = SEVERITY_LEVELS.get(
                node.severity.upper(), node.severity.lower()
            )

        if node.exposure:
            extension["xSafety:exposure"] = EXPOSURE_LEVELS.get(
                node.exposure.upper(), node.exposure.lower()
            )

        if node.controllability:
            extension["xSafety:controllability"] = CONTROLLABILITY_LEVELS.get(
                node.controllability.upper(), node.controllability.lower()
            )

        if node.asil:
            extension["xSafety:safetyIntegrityLevel"] = ASIL_LEVELS.get(
                node.asil.upper(), node.asil.lower()
            )

        element = {
            "@type": "Bundle",
            "spdxId": spdx_id,
            "name": node.uid,
            "description": node.statement or node.title,
            "primaryPurpose": "requirement",
            "extension": [extension],
        }

        if node.rationale:
            element["comment"] = node.rationale

        self._add_element(element)
        return element

    def build_safety_goal_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build a Bundle element for a safety goal (SG-*).

        Args:
            node: StrictDoc safety goal node.

        Returns:
            SPDX Bundle element.
        """
        spdx_id = self.make_spdx_id("element", node.uid)

        extension = {
            "type": "xSafety:SafetyGoalExtension",
        }

        if node.asil:
            extension["xSafety:safetyIntegrityLevel"] = ASIL_LEVELS.get(
                node.asil.upper(), node.asil.lower()
            )

        element = {
            "@type": "Bundle",
            "spdxId": spdx_id,
            "name": node.uid,
            "description": node.statement or node.title,
            "primaryPurpose": "requirement",
            "extension": [extension],
        }

        if node.rationale:
            element["comment"] = node.rationale

        self._add_element(element)
        return element

    def build_requirement_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build a Bundle element for a safety requirement (TSR/SSR/HSR-*).

        Args:
            node: StrictDoc requirement node.

        Returns:
            SPDX Bundle element.
        """
        spdx_id = self.make_spdx_id("element", node.uid)

        # Determine requirement type from UID prefix
        req_type_key = node.get_requirement_type()
        req_type = REQUIREMENT_TYPES.get(req_type_key, "functional")

        extension = {
            "type": "xSafety:SafetyRequirementExtension",
            "xSafety:requirementType": req_type,
        }

        if node.asil:
            extension["xSafety:safetyIntegrityLevel"] = ASIL_LEVELS.get(
                node.asil.upper(), node.asil.lower()
            )

        element = {
            "@type": "Bundle",
            "spdxId": spdx_id,
            "name": node.uid,
            "description": node.statement or node.title,
            "primaryPurpose": "requirement",
            "extension": [extension],
        }

        if node.rationale:
            element["comment"] = node.rationale

        self._add_element(element)
        return element

    def build_test_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build a Bundle element for a test case (TC-*).

        Args:
            node: StrictDoc test case node.

        Returns:
            SPDX Bundle element.
        """
        spdx_id = self.make_spdx_id("element", node.uid)

        # Default to integration test if not specified
        test_type = TEST_TYPES.get("INTEGRATION", "integrationTest")

        extension = {
            "type": "xSafety:SafetyTestExtension",
            "xSafety:testType": test_type,
        }

        if node.asil:
            extension["xSafety:safetyIntegrityLevel"] = ASIL_LEVELS.get(
                node.asil.upper(), node.asil.lower()
            )

        element = {
            "@type": "Bundle",
            "spdxId": spdx_id,
            "name": node.uid,
            "description": node.statement or node.title,
            "primaryPurpose": "test",
            "extension": [extension],
        }

        if node.rationale:
            element["comment"] = node.rationale

        self._add_element(element)
        return element

    def build_evidence_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build a software_File element for evidence (EVID-*).

        Args:
            node: StrictDoc evidence node.

        Returns:
            SPDX software_File element.
        """
        spdx_id = self.make_spdx_id("evidence", node.uid)

        # Default to test result evidence
        evidence_type = EVIDENCE_TYPES.get("TEST_RESULT", "testResult")

        extension = {
            "type": "xSafety:SafetyEvidenceExtension",
            "xSafety:evidenceType": evidence_type,
        }

        element = {
            "@type": "software_File",
            "spdxId": spdx_id,
            "name": node.uid,
            "description": node.statement or node.title,
            "primaryPurpose": "evidence",
            "extension": [extension],
        }

        self._add_element(element)
        return element

    # =========================================================================
    # Source File Elements
    # =========================================================================

    def build_file_element(
        self,
        file_path: Path,
        source_root: Path | None = None,
    ) -> dict[str, Any]:
        """
        Build a software_File element for a source file.

        Args:
            file_path: Path to the source file.
            source_root: Optional root path for relative path calculation.

        Returns:
            SPDX software_File element.
        """
        if source_root:
            try:
                relative_path = file_path.relative_to(source_root)
            except ValueError:
                relative_path = file_path
        else:
            relative_path = file_path

        # Use relative path as identifier
        file_id = str(relative_path).replace("\\", "/")
        spdx_id = self.make_spdx_id("file", file_id)

        # Check if already added
        if spdx_id in self._element_ids:
            return {"spdxId": spdx_id}

        element = {
            "@type": "software_File",
            "spdxId": spdx_id,
            "name": file_path.name,
            "description": f"Source file: {relative_path}",
            "primaryPurpose": "source",
        }

        self._add_element(element)
        return element

    def build_file_with_range(
        self,
        range_link: RangeLink,
        source_root: Path | None = None,
    ) -> dict[str, Any]:
        """
        Build a software_File element with PositionalRange snippet.

        Args:
            range_link: RangeLink with file location and range.
            source_root: Optional root path for relative path.

        Returns:
            SPDX software_File element with contentInformationType.
        """
        if source_root:
            try:
                relative_path = range_link.file_path.relative_to(source_root)
            except ValueError:
                relative_path = range_link.file_path
        else:
            relative_path = range_link.file_path

        # Create unique ID including line range
        file_id = f"{relative_path}#L{range_link.line_start}-L{range_link.line_end}"
        file_id = file_id.replace("\\", "/")
        spdx_id = self.make_spdx_id("file", file_id)

        element = {
            "@type": "software_File",
            "spdxId": spdx_id,
            "name": range_link.file_path.name,
            "description": f"Source: {relative_path} lines {range_link.line_start}-{range_link.line_end}",
            "primaryPurpose": "source",
            "contentInformationType": [
                {
                    "type": "PositionalRange",
                    "beginPointer": {
                        "type": "LineCharPointer",
                        "lineNumber": range_link.line_start,
                    },
                    "endPointer": {
                        "type": "LineCharPointer",
                        "lineNumber": range_link.line_end,
                    },
                }
            ],
        }

        if range_link.snippet:
            element["comment"] = f"Snippet: {range_link.snippet[:200]}"

        self._add_element(element)
        return element

    # =========================================================================
    # Generic Element Builder
    # =========================================================================

    def build_node_element(self, node: StrictDocNode) -> dict[str, Any]:
        """
        Build appropriate SPDX element based on node type.

        Args:
            node: StrictDoc node.

        Returns:
            SPDX element dictionary.
        """
        req_type = node.get_requirement_type()

        if req_type == "HAZ":
            return self.build_hazard_element(node)
        if req_type == "SG":
            return self.build_safety_goal_element(node)
        if req_type in ("TSR", "SSR", "HSR", "SWA", "REQ"):
            return self.build_requirement_element(node)
        if req_type == "TC":
            return self.build_test_element(node)
        if req_type == "EVID":
            return self.build_evidence_element(node)

        # Default: generic Bundle
        return self.build_requirement_element(node)

    @property
    def elements(self) -> list[dict[str, Any]]:
        """Get all built elements."""
        return self._elements.copy()

    @property
    def element_ids(self) -> set[str]:
        """Get all element SPDX IDs."""
        return self._element_ids.copy()
