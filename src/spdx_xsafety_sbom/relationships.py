"""
SPDX 3.0.1 Relationship builder.

This module builds SPDX relationships between elements:
- descendantOf: Parent-child requirement hierarchy
- hasTestCase: Requirement to test case
- hasEvidence: Test/requirement to evidence
- testedOn: Requirement to source file (via @sdoc markers)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom.constants import RELATIONSHIP_TYPES
from spdx_xsafety_sbom.models import RangeLink, StrictDocNode

if TYPE_CHECKING:
    from spdx_xsafety_sbom.spdx_builder import SPDX3Builder

logger = logging.getLogger(__name__)


class RelationshipBuilder:
    """Builder for SPDX 3.0.1 relationships."""

    def __init__(self, spdx_builder: SPDX3Builder) -> None:
        """
        Initialize the relationship builder.

        Args:
            spdx_builder: SPDX3Builder instance for ID generation.
        """
        self.spdx_builder = spdx_builder
        self._relationships: list[dict[str, Any]] = []
        self._relationship_count = 0

    def build_relationship(
        self,
        from_id: str,
        to_ids: list[str],
        relationship_type: str,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Build a single SPDX Relationship.

        Args:
            from_id: SPDX ID of the source element.
            to_ids: List of SPDX IDs of target elements.
            relationship_type: Type of relationship.
            comment: Optional comment.

        Returns:
            SPDX Relationship element.
        """
        self._relationship_count += 1
        rel_id = self.spdx_builder.make_spdx_id(
            "relationship", f"rel-{self._relationship_count}"
        )

        # Map relationship type to SPDX vocabulary
        spdx_rel_type = RELATIONSHIP_TYPES.get(relationship_type, relationship_type)

        relationship = {
            "@type": "Relationship",
            "spdxId": rel_id,
            "relationshipType": spdx_rel_type,
            "from": from_id,
            "to": to_ids,
        }

        if comment:
            relationship["comment"] = comment

        self._relationships.append(relationship)
        return relationship

    def build_hierarchy_relationships(
        self,
        nodes: dict[str, StrictDocNode],
    ) -> list[dict[str, Any]]:
        """
        Build descendantOf relationships from parent_uids.

        Creates:
        - Safety Goal descendantOf Hazard
        - TSR descendantOf Safety Goal
        - SSR descendantOf TSR
        - etc.

        Args:
            nodes: Dictionary of UID to StrictDocNode.

        Returns:
            List of Relationship elements.
        """
        relationships: list[dict[str, Any]] = []

        for uid, node in nodes.items():
            if not node.parent_uids:
                continue

            # Build descendantOf relationship for each parent
            child_spdx_id = self.spdx_builder.make_spdx_id("element", uid)

            for parent_uid in node.parent_uids:
                if parent_uid not in nodes:
                    logger.warning("Parent UID %s not found for %s", parent_uid, uid)
                    continue

                parent_spdx_id = self.spdx_builder.make_spdx_id("element", parent_uid)

                rel = self.build_relationship(
                    from_id=child_spdx_id,
                    to_ids=[parent_spdx_id],
                    relationship_type="descendantOf",
                    comment=f"{uid} derived from {parent_uid}",
                )
                relationships.append(rel)

        logger.info("Built %d hierarchy relationships", len(relationships))
        return relationships

    def build_test_relationships(
        self,
        nodes: dict[str, StrictDocNode],
    ) -> list[dict[str, Any]]:
        """
        Build hasTestCase relationships between requirements and tests.

        Args:
            nodes: Dictionary of UID to StrictDocNode.

        Returns:
            List of Relationship elements.
        """
        relationships: list[dict[str, Any]] = []

        # Find test cases (TC-* nodes)
        test_cases = {
            uid: node
            for uid, node in nodes.items()
            if node.get_requirement_type() == "TC"
        }

        for tc_uid, tc_node in test_cases.items():
            tc_spdx_id = self.spdx_builder.make_spdx_id("element", tc_uid)

            # Tests link to their parent requirements
            for parent_uid in tc_node.parent_uids:
                if parent_uid in nodes:
                    req_spdx_id = self.spdx_builder.make_spdx_id("element", parent_uid)

                    rel = self.build_relationship(
                        from_id=req_spdx_id,
                        to_ids=[tc_spdx_id],
                        relationship_type="hasTestCase",
                        comment=f"{parent_uid} has test case {tc_uid}",
                    )
                    relationships.append(rel)

        logger.info("Built %d test relationships", len(relationships))
        return relationships

    def build_evidence_relationships(
        self,
        nodes: dict[str, StrictDocNode],
    ) -> list[dict[str, Any]]:
        """
        Build hasEvidence relationships.

        Args:
            nodes: Dictionary of UID to StrictDocNode.

        Returns:
            List of Relationship elements.
        """
        relationships: list[dict[str, Any]] = []

        # Find evidence nodes (EVID-*)
        evidence_nodes = {
            uid: node
            for uid, node in nodes.items()
            if node.get_requirement_type() == "EVID"
        }

        for evid_uid, evid_node in evidence_nodes.items():
            evid_spdx_id = self.spdx_builder.make_spdx_id("evidence", evid_uid)

            # Evidence links to parent items (tests or requirements)
            for parent_uid in evid_node.parent_uids:
                if parent_uid in nodes:
                    parent_type = nodes[parent_uid].get_requirement_type()

                    # Use element or evidence prefix based on parent type
                    if parent_type == "EVID":
                        parent_spdx_id = self.spdx_builder.make_spdx_id(
                            "evidence", parent_uid
                        )
                    else:
                        parent_spdx_id = self.spdx_builder.make_spdx_id(
                            "element", parent_uid
                        )

                    rel = self.build_relationship(
                        from_id=parent_spdx_id,
                        to_ids=[evid_spdx_id],
                        relationship_type="hasEvidence",
                        comment=f"{parent_uid} has evidence {evid_uid}",
                    )
                    relationships.append(rel)

        logger.info("Built %d evidence relationships", len(relationships))
        return relationships

    def build_source_relationships(
        self,
        source_links: dict[str, list[RangeLink]],
        source_root: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Build testedOn relationships from @sdoc markers.

        Args:
            source_links: Dictionary mapping UID to RangeLinks.
            source_root: Optional source root for path calculation.

        Returns:
            List of Relationship elements.
        """
        relationships: list[dict[str, Any]] = []

        for uid, links in source_links.items():
            req_spdx_id = self.spdx_builder.make_spdx_id("element", uid)

            for link in links:
                # Build file element with range
                file_element = self.spdx_builder.build_file_with_range(
                    link, source_root
                )
                file_spdx_id = file_element["spdxId"]

                rel = self.build_relationship(
                    from_id=req_spdx_id,
                    to_ids=[file_spdx_id],
                    relationship_type="testedOn",
                    comment=f"{uid} implemented in {link.file_path.name}:{link.line_start}-{link.line_end}",
                )
                relationships.append(rel)

        logger.info("Built %d source relationships", len(relationships))
        return relationships

    def build_all_relationships(
        self,
        nodes: dict[str, StrictDocNode],
        source_links: dict[str, list[RangeLink]] | None = None,
        source_root: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Build all relationships from parsed data.

        Args:
            nodes: Dictionary of UID to StrictDocNode.
            source_links: Optional @sdoc marker links.
            source_root: Optional source root path.

        Returns:
            List of all Relationship elements.
        """
        all_relationships: list[dict[str, Any]] = []

        # Build hierarchy relationships
        all_relationships.extend(self.build_hierarchy_relationships(nodes))

        # Build test relationships
        all_relationships.extend(self.build_test_relationships(nodes))

        # Build evidence relationships
        all_relationships.extend(self.build_evidence_relationships(nodes))

        # Build source relationships if markers provided
        if source_links:
            all_relationships.extend(
                self.build_source_relationships(source_links, source_root)
            )

        logger.info("Built %d total relationships", len(all_relationships))
        return all_relationships

    @property
    def relationships(self) -> list[dict[str, Any]]:
        """Get all built relationships."""
        return self._relationships.copy()


def build_relationships(
    spdx_builder: SPDX3Builder,
    nodes: dict[str, StrictDocNode],
    source_links: dict[str, list[RangeLink]] | None = None,
    source_root: str | None = None,
) -> list[dict[str, Any]]:
    """
    Convenience function to build all relationships.

    Args:
        spdx_builder: SPDX3Builder instance.
        nodes: Dictionary of UID to StrictDocNode.
        source_links: Optional @sdoc marker links.
        source_root: Optional source root path.

    Returns:
        List of Relationship elements.
    """
    builder = RelationshipBuilder(spdx_builder)
    return builder.build_all_relationships(nodes, source_links, source_root)
