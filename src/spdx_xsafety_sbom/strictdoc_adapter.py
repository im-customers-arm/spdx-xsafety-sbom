"""
StrictDoc library adapter.

Provides direct access to StrictDoc's Python API for parsing .sdoc files
and extracting requirements with full traceability information.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom.models import RangeLink, StrictDocNode

if TYPE_CHECKING:
    from strictdoc.backend.sdoc.models.node import SDocNode as StrictDocSDocNode
    from strictdoc.core.traceability_index import TraceabilityIndex

logger = logging.getLogger(__name__)

# Type alias for source code markers
# These are internal StrictDoc types, using Any to avoid import dependency
MarkerType = Any


class StrictDocAdapter:
    """
    Adapter for StrictDoc library integration.

    Parses .sdoc files directly using StrictDoc's native parser
    and provides access to requirements and traceability data.
    """

    def __init__(self, project_path: Path) -> None:
        """
        Initialize the adapter.

        Args:
            project_path: Path to StrictDoc project root (containing .sdoc files)
        """
        self.project_path = Path(project_path).resolve()
        self._traceability_index: TraceabilityIndex | None = None
        self._nodes: dict[str, StrictDocNode] = {}
        self._sdoc_nodes: dict[str, StrictDocSDocNode] = {}  # Keep refs to original nodes

    def parse(self) -> dict[str, StrictDocNode]:
        """
        Parse StrictDoc project and return nodes indexed by UID.

        Returns:
            Dictionary mapping UID to StrictDocNode objects.

        Raises:
            FileNotFoundError: If project path does not exist.
        """
        if not self.project_path.exists():
            raise FileNotFoundError(
                f"StrictDoc project path not found: {self.project_path}"
            )

        self._load_project()
        self._extract_nodes()
        self._build_child_relationships()

        logger.info("Parsed %d nodes with UIDs", len(self._nodes))
        return self._nodes

    def _load_project(self) -> None:
        """Load StrictDoc project using library API."""
        from strictdoc.core.project_config import ProjectConfigLoader
        from strictdoc.core.traceability_index_builder import TraceabilityIndexBuilder
        from strictdoc.helpers.parallelizer import NullParallelizer

        # Load project config - use load() which takes input path directly
        # This is simpler and handles .sdoc file discovery
        config = ProjectConfigLoader.load(
            input_path=str(self.project_path),
            output_dir=None,
        )

        # Build traceability index (this also parses all documents)
        # Using NullParallelizer for single-threaded operation
        parallelizer = NullParallelizer()

        self._traceability_index = TraceabilityIndexBuilder.create(
            project_config=config,
            parallelizer=parallelizer,
            skip_source_files=False,  # We want source file traceability
        )

        logger.debug("Loaded StrictDoc project from: %s", self.project_path)

    def _extract_nodes(self) -> None:
        """Extract all requirement nodes from the traceability index."""
        if self._traceability_index is None:
            raise RuntimeError("Project not loaded. Call _load_project() first.")

        # Iterate through all document iterators to get nodes
        for doc_iterator in self._traceability_index.document_iterators.values():
            for node in self._iterate_requirement_nodes(doc_iterator):
                if not hasattr(node, "reserved_uid") or node.reserved_uid is None:
                    continue

                uid = node.reserved_uid
                sdoc_node = self._convert_node(node)
                self._nodes[uid] = sdoc_node
                self._sdoc_nodes[uid] = node  # Keep reference for source links

    def _iterate_requirement_nodes(self, doc_iterator: Any) -> Iterator[StrictDocSDocNode]:
        """Iterate all requirement nodes from a document iterator."""
        # doc_iterator has all_content which yields tuples of (node, info)
        if hasattr(doc_iterator, "all_content"):
            for item in doc_iterator.all_content():
                # all_content() returns tuples (node, additional_info)
                node = item[0] if isinstance(item, tuple) else item
                # Check if this is a requirement-like node (has UID capability)
                if hasattr(node, "reserved_uid"):
                    yield node

    def _convert_node(self, node: StrictDocSDocNode) -> StrictDocNode:
        """Convert StrictDoc SDocNode to our StrictDocNode model."""
        return StrictDocNode(
            uid=node.reserved_uid or "",
            title=node.reserved_title if hasattr(node, "reserved_title") else None,
            statement=self._extract_statement(node),
            rationale=self._extract_rationale(node),
            comment=self._extract_comment(node),
            node_type=self._get_node_type(node),
            asil=self._get_field(node, "ASIL"),
            severity=self._get_field(node, "SEVERITY"),
            exposure=self._get_field(node, "EXPOSURE"),
            controllability=self._get_field(node, "CONTROLLABILITY"),
            parent_uids=self._extract_parent_uids(node),
            document_path=self._get_document_path(node),
        )

    def _extract_statement(self, node: StrictDocSDocNode) -> str | None:
        """Extract statement text from node."""
        if not hasattr(node, "reserved_statement"):
            return None
        stmt = node.reserved_statement
        if stmt is None:
            return None
        # Statement might be a string or an object with get_text() method
        if hasattr(stmt, "get_text"):
            return stmt.get_text()
        if hasattr(stmt, "statement_text"):
            return stmt.statement_text
        return str(stmt) if stmt else None

    def _extract_rationale(self, node: StrictDocSDocNode) -> str | None:
        """Extract rationale from node."""
        if not hasattr(node, "reserved_rationale"):
            return None
        rat = node.reserved_rationale
        if rat is None:
            return None
        if hasattr(rat, "get_text"):
            return rat.get_text()
        return str(rat) if rat else None

    def _extract_comment(self, node: StrictDocSDocNode) -> str | None:
        """Extract first comment from node."""
        if not hasattr(node, "reserved_comments"):
            return None
        comments = node.reserved_comments
        if not comments:
            return None
        first_comment = comments[0]
        if hasattr(first_comment, "get_text"):
            return first_comment.get_text()
        if hasattr(first_comment, "comment"):
            return first_comment.comment
        return str(first_comment) if first_comment else None

    def _get_node_type(self, node: StrictDocSDocNode) -> str:
        """Get the node type (REQUIREMENT, TEXT, etc.)."""
        if hasattr(node, "requirement_type") and node.requirement_type:
            return node.requirement_type
        if hasattr(node, "node_type") and node.node_type:
            return node.node_type
        return "REQUIREMENT"

    def _get_field(self, node: StrictDocSDocNode, name: str) -> str | None:
        """Get custom field value by name."""
        if not hasattr(node, "ordered_fields_lookup"):
            return None
        lookup = node.ordered_fields_lookup
        if lookup is None:
            return None
        fields = lookup.get(name, [])
        if not fields:
            return None
        field = fields[0]
        # In StrictDoc 0.16.x, field values are in the 'parts' list
        if hasattr(field, "parts") and field.parts:
            return str(field.parts[0]) if field.parts[0] else None
        # Fallback to field_value or field_value_multiline
        if hasattr(field, "field_value") and field.field_value:
            return field.field_value
        if hasattr(field, "field_value_multiline") and field.field_value_multiline:
            return field.field_value_multiline
        return None

    def _extract_parent_uids(self, node: StrictDocSDocNode) -> list[str]:
        """Extract parent UIDs from node relations."""
        parents: list[str] = []

        if not hasattr(node, "relations") or node.relations is None:
            return parents

        for relation in node.relations:
            # Get the reference UID
            ref_uid = getattr(relation, "ref_uid", None)
            if not ref_uid:
                continue

            # Check relation type - we want Parent, Refines, Derives types
            ref_type = getattr(relation, "ref_type", "Parent")
            if ref_type is None:
                ref_type = "Parent"

            ref_type_str = str(ref_type).lower()
            if ref_type_str in ("parent", "refines", "derives", "none"):
                parents.append(ref_uid)

        return parents

    def _get_document_path(self, node: StrictDocSDocNode) -> Path | None:
        """Get source document path from node."""
        if not hasattr(node, "document") or node.document is None:
            return None
        doc = node.document
        if hasattr(doc, "meta") and doc.meta and hasattr(doc.meta, "input_doc_full_path"):
            return Path(doc.meta.input_doc_full_path)
        return None

    def _build_child_relationships(self) -> None:
        """Populate child_uids from parent_uids."""
        for uid, node in self._nodes.items():
            for parent_uid in node.parent_uids:
                if parent_uid in self._nodes:
                    self._nodes[parent_uid].child_uids.append(uid)

    def get_source_links(self) -> dict[str, list[RangeLink]]:
        """
        Get source file traceability links.

        StrictDoc parses @sdoc[UID] markers automatically during
        traceability index construction.

        Returns:
            Dictionary mapping UID to list of RangeLinks.

        Raises:
            RuntimeError: If parse() has not been called.
        """
        if self._traceability_index is None:
            raise RuntimeError("Must call parse() first")

        links: dict[str, list[RangeLink]] = {}

        for uid, sdoc_node in self._sdoc_nodes.items():
            try:
                # get_requirement_file_links returns List[Tuple[str, List[Marker]]]
                file_links = self._traceability_index.get_requirement_file_links(
                    sdoc_node
                )
            except Exception as e:
                logger.debug("Error getting file links for %s: %s", uid, e)
                continue

            if not file_links:
                continue

            uid_links: list[RangeLink] = []
            for file_path, markers in file_links:
                for marker in markers:
                    range_link = self._convert_marker_to_range_link(
                        file_path, marker, uid
                    )
                    if range_link:
                        uid_links.append(range_link)

            if uid_links:
                links[uid] = uid_links

        total = sum(len(v) for v in links.values())
        logger.info("Found %d source links across %d UIDs", total, len(links))
        return links

    def _convert_marker_to_range_link(
        self, file_path: str, marker: MarkerType, uid: str
    ) -> RangeLink | None:
        """Convert a StrictDoc marker to a RangeLink."""
        # Get line numbers from the marker
        line_start = getattr(marker, "ng_range_line_begin", None)
        line_end = getattr(marker, "ng_range_line_end", None)

        # Fallback to source line if range not available
        if line_start is None:
            line_start = getattr(marker, "ng_source_line_begin", 1)
        if line_end is None:
            line_end = line_start

        if line_start is None:
            return None

        return RangeLink(
            file_path=Path(file_path),
            line_start=line_start,
            line_end=line_end or line_start,
            uid=uid,
            snippet=None,
        )

    # Convenience methods

    def get_nodes_by_type(self, prefix: str) -> list[StrictDocNode]:
        """Get nodes with UID starting with prefix."""
        return [n for n in self._nodes.values() if n.uid.startswith(prefix)]

    def get_hazards(self) -> list[StrictDocNode]:
        """Get HAZ-* nodes."""
        return self.get_nodes_by_type("HAZ")

    def get_safety_goals(self) -> list[StrictDocNode]:
        """Get SG-* nodes."""
        return self.get_nodes_by_type("SG")

    def get_requirements(self) -> list[StrictDocNode]:
        """Get TSR-*, SSR-*, HSR-* nodes."""
        return (
            self.get_nodes_by_type("TSR")
            + self.get_nodes_by_type("SSR")
            + self.get_nodes_by_type("HSR")
        )

    def get_test_cases(self) -> list[StrictDocNode]:
        """Get TC-* nodes."""
        return self.get_nodes_by_type("TC")

    def get_evidence(self) -> list[StrictDocNode]:
        """Get EVID-* nodes."""
        return self.get_nodes_by_type("EVID")


def parse_strictdoc_project(project_path: Path | str) -> dict[str, StrictDocNode]:
    """
    Convenience function to parse a StrictDoc project.

    Args:
        project_path: Path to project root containing .sdoc files.

    Returns:
        Dictionary mapping UID to StrictDocNode.
    """
    adapter = StrictDocAdapter(Path(project_path))
    return adapter.parse()
