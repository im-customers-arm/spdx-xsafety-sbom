"""
StrictDoc JSON export parser.

This module parses StrictDoc's JSON export format to extract:
- Requirements with UIDs
- Safety metadata (ASIL, HARA ratings)
- Traceability links (parent/child relationships)
- Document structure

Supports StrictDoc export format v3.x with DOCUMENTS/NODES structure.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from spdx_xsafety_sbom.models import StrictDocNode

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _walk_nodes(nodes: list[dict[str, Any]] | None) -> Iterator[dict[str, Any]]:
    """Recursively walk through StrictDoc node tree (handles nested NODES)."""
    for node in nodes or []:
        yield node
        yield from _walk_nodes(node.get("NODES"))


class StrictDocParser:
    """Parser for StrictDoc JSON export files."""

    def __init__(self, export_path: Path) -> None:
        """
        Initialize the StrictDoc parser.

        Args:
            export_path: Path to the StrictDoc JSON export directory
                        (typically build/strictdoc-json/)
        """
        self.export_path = Path(export_path)
        self._nodes: dict[str, StrictDocNode] = {}
        self._documents: list[dict[str, Any]] = []

    def parse(self) -> dict[str, StrictDocNode]:
        """
        Parse all StrictDoc JSON export files.

        Returns:
            Dictionary mapping UID to StrictDocNode objects.
        """
        if not self.export_path.exists():
            raise FileNotFoundError(
                f"StrictDoc export path not found: {self.export_path}"
            )

        # Find all .json files in the export directory
        json_files = list(self.export_path.glob("**/*.json"))

        if not json_files:
            logger.warning("No JSON files found in %s", self.export_path)
            return {}

        logger.info("Found %d JSON files to parse", len(json_files))

        for json_file in json_files:
            self._parse_file(json_file)

        # Build child relationships (reverse of parent links)
        self._build_child_relationships()

        logger.info("Parsed %d nodes with UIDs", len(self._nodes))
        return self._nodes

    def _parse_file(self, json_file: Path) -> None:
        """Parse a single JSON export file."""
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse %s: %s", json_file, e)
            return

        # Handle DOCUMENTS array format (StrictDoc standard export)
        if isinstance(data, dict) and "DOCUMENTS" in data:
            for doc in data["DOCUMENTS"]:
                self._parse_document_nodes(doc, json_file)
        elif isinstance(data, dict):
            if "document" in data:
                self._parse_document_nodes(data["document"], json_file)
            elif "NODES" in data:
                self._parse_all_nodes(data["NODES"], json_file)
            elif "nodes" in data:
                self._parse_all_nodes(data["nodes"], json_file)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "NODES" in item:
                    self._parse_all_nodes(item["NODES"], json_file)

    def _parse_document_nodes(self, doc: dict[str, Any], source_file: Path) -> None:
        """Parse all nodes from a document using recursive walk."""
        self._documents.append(doc)
        # Support both NODES (StrictDoc standard) and sections (alternative format)
        nodes = doc.get("NODES") or doc.get("nodes") or doc.get("sections", [])
        self._parse_all_nodes(nodes, source_file)

    def _parse_all_nodes(self, nodes: list[dict[str, Any]], source_file: Path) -> None:
        """Parse all nodes recursively using _walk_nodes."""
        for node in _walk_nodes(nodes):
            self._parse_node(node, source_file)

    def _parse_node(self, node: dict[str, Any], source_file: Path) -> None:
        """Parse a single requirement/section node."""
        # Get UID (uppercase preferred for StrictDoc format)
        uid = node.get("UID") or node.get("uid")
        if not uid:
            return

        # Skip if already parsed (avoid duplicates)
        if uid in self._nodes:
            logger.debug("Skipping duplicate node: %s", uid)
            return

        # Get node type
        node_type = node.get("TYPE") or node.get("type") or node.get("node_type") or "REQUIREMENT"

        # Skip TEXT and SECTION nodes without meaningful UIDs
        if node_type in ("TEXT", "SECTION") and not any(
            uid.startswith(prefix) for prefix in ("HAZ", "SG", "TSR", "SSR", "HSR", "TC", "EVID", "REQ")
        ):
            return

        # Extract basic fields
        title = node.get("TITLE") or node.get("title")

        # Statement can be in various locations
        statement = (
            node.get("STATEMENT")
            or node.get("statement")
            or node.get("TEXT")
            or node.get("text")
        )

        # Handle statement as dict (StrictDoc nested format)
        if isinstance(statement, dict):
            statement = statement.get("text") or statement.get("content")

        rationale = node.get("RATIONALE") or node.get("rationale")
        if isinstance(rationale, dict):
            rationale = rationale.get("text") or rationale.get("content")

        comment = node.get("COMMENT") or node.get("comment")
        if isinstance(comment, dict):
            comment = comment.get("text") or comment.get("content")

        # Extract safety-specific fields (directly on node for StrictDoc format)
        asil = node.get("ASIL") or node.get("asil")
        severity = node.get("SEVERITY") or node.get("severity")
        exposure = node.get("EXPOSURE") or node.get("exposure")
        controllability = node.get("CONTROLLABILITY") or node.get("controllability")
        situation = node.get("SITUATION") or node.get("situation")

        # Extract parent links from RELATIONS
        parent_uids = self._extract_parent_uids(node)

        # Create node
        sdoc_node = StrictDocNode(
            uid=uid,
            title=title,
            statement=statement,
            rationale=rationale,
            comment=comment,
            node_type=node_type,
            asil=asil,
            severity=severity,
            exposure=exposure,
            controllability=controllability,
            parent_uids=parent_uids,
            document_path=source_file,
        )

        self._nodes[uid] = sdoc_node
        logger.debug("Parsed node: %s (type=%s, parents=%s)", uid, sdoc_node.get_requirement_type(), parent_uids)

    def _extract_parent_uids(self, node: dict[str, Any]) -> list[str]:
        """Extract parent UIDs from RELATIONS field."""
        parent_uids: list[str] = []

        relations = node.get("RELATIONS") or node.get("relations") or []

        for relation in relations:
            if isinstance(relation, dict):
                # Get relation type
                rel_type = (
                    relation.get("TYPE") 
                    or relation.get("type") 
                    or relation.get("role") 
                    or ""
                )
                
                # Get target UID - StrictDoc uses VALUE, not UID
                rel_uid = (
                    relation.get("VALUE")  # StrictDoc standard format
                    or relation.get("UID") 
                    or relation.get("uid") 
                    or relation.get("target")
                )

                # Only include Parent relations (not File relations)
                if rel_uid and rel_type.lower() in ("parent", "refines", "derives"):
                    parent_uids.append(rel_uid)
            elif isinstance(relation, str):
                # Handle string format (assume it's a parent UID)
                parent_uids.append(relation)

        return parent_uids

    def _build_child_relationships(self) -> None:
        """Build child_uids from parent_uids (reverse relationships)."""
        for uid, node in self._nodes.items():
            for parent_uid in node.parent_uids:
                if parent_uid in self._nodes:
                    self._nodes[parent_uid].child_uids.append(uid)

    def get_nodes_by_type(self, prefix: str) -> list[StrictDocNode]:
        """
        Get all nodes with a specific UID prefix.

        Args:
            prefix: UID prefix (e.g., "SSR", "TSR", "HAZ")

        Returns:
            List of matching nodes.
        """
        return [
            node
            for node in self._nodes.values()
            if node.uid.startswith(prefix)
        ]

    def get_hazards(self) -> list[StrictDocNode]:
        """Get all hazard nodes (HAZ-*)."""
        return self.get_nodes_by_type("HAZ")

    def get_safety_goals(self) -> list[StrictDocNode]:
        """Get all safety goal nodes (SG-*)."""
        return self.get_nodes_by_type("SG")

    def get_requirements(self) -> list[StrictDocNode]:
        """Get all requirement nodes (TSR-*, SSR-*, HSR-*)."""
        return (
            self.get_nodes_by_type("TSR")
            + self.get_nodes_by_type("SSR")
            + self.get_nodes_by_type("HSR")
        )

    def get_test_cases(self) -> list[StrictDocNode]:
        """Get all test case nodes (TC-*)."""
        return self.get_nodes_by_type("TC")

    def get_evidence(self) -> list[StrictDocNode]:
        """Get all evidence nodes (EVID-*)."""
        return self.get_nodes_by_type("EVID")


def parse_strictdoc_export(export_path: Path | str) -> dict[str, StrictDocNode]:
    """
    Convenience function to parse StrictDoc export.

    Args:
        export_path: Path to StrictDoc JSON export directory.

    Returns:
        Dictionary mapping UID to StrictDocNode.
    """
    parser = StrictDocParser(Path(export_path))
    return parser.parse()