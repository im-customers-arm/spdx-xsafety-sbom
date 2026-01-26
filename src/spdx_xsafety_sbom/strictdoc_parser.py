"""
StrictDoc parser module.

This module provides parsing of StrictDoc artifacts to extract:
- Requirements with UIDs
- Safety metadata (ASIL, HARA ratings)
- Traceability links (parent/child relationships)
- Document structure

Supports two modes:
1. Native mode: Uses StrictDoc library directly for .sdoc files
2. JSON mode: Parses StrictDoc's JSON export format (fallback)
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

# Check if StrictDoc library is available
_STRICTDOC_AVAILABLE = False
try:
    from strictdoc.backend.sdoc.reader import SDReader

    _STRICTDOC_AVAILABLE = True
except ImportError:
    SDReader = None  # type: ignore[misc, assignment]


def is_strictdoc_available() -> bool:
    """Check if StrictDoc library is available for native parsing."""
    return _STRICTDOC_AVAILABLE


def _walk_nodes(nodes: list[dict[str, Any]] | None) -> Iterator[dict[str, Any]]:
    """Recursively walk through StrictDoc node tree (handles nested NODES)."""
    for node in nodes or []:
        yield node
        yield from _walk_nodes(node.get("NODES"))


class StrictDocParser:
    """
    Parser for StrictDoc artifacts.

    Supports both native .sdoc file parsing (when StrictDoc is installed)
    and JSON export parsing (fallback mode).
    """

    def __init__(
        self,
        path: Path,
        *,
        prefer_native: bool = True,
    ) -> None:
        """
        Initialize the StrictDoc parser.

        Args:
            path: Path to StrictDoc content. Can be:
                - A directory containing .sdoc files (native mode)
                - A directory containing JSON export files
                - A single .sdoc file
                - A single .json file
            prefer_native: If True, prefer native parsing when available.
        """
        self.path = Path(path)
        # Legacy alias for backward compatibility
        self.export_path = self.path
        self.prefer_native = prefer_native and _STRICTDOC_AVAILABLE
        self._nodes: dict[str, StrictDocNode] = {}
        self._documents: list[Any] = []

    def parse(self) -> dict[str, StrictDocNode]:
        """
        Parse StrictDoc artifacts.

        Returns:
            Dictionary mapping UID to StrictDocNode objects.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"StrictDoc path not found: {self.path}")

        # Determine parsing mode based on path and available libraries
        if self.path.is_file():
            if self.path.suffix == ".sdoc" and self.prefer_native:
                self._parse_native_file(self.path)
            elif self.path.suffix == ".json":
                self._parse_json_file(self.path)
            else:
                raise ValueError(f"Unsupported file type: {self.path.suffix}")
        else:
            # Directory: check for custom grammar or config
            sdoc_files = list(self.path.glob("**/*.sdoc"))
            json_files = list(self.path.glob("**/*.json"))
            has_custom_grammar = (
                (self.path / "strictdoc.toml").exists()
                or list(self.path.glob("*.sgra"))
            )

            if sdoc_files and self.prefer_native:
                if has_custom_grammar:
                    # Use full StrictDoc export pipeline for custom grammars
                    logger.info(
                        "Detected custom grammar, using StrictDoc export for %d .sdoc files",
                        len(sdoc_files),
                    )
                    if self._parse_native_directory(self.path):
                        # Success - JSON parsing happened in _parse_native_directory
                        pass
                    elif json_files:
                        # Fallback to existing JSON files
                        logger.info(
                            "Falling back to JSON export parsing for %d .json files",
                            len(json_files),
                        )
                        for json_file in json_files:
                            self._parse_json_file(json_file)
                    else:
                        logger.warning(
                            "StrictDoc export failed and no JSON files found"
                        )
                        return {}
                else:
                    # Simple native parsing (default grammar)
                    logger.info(
                        "Using native StrictDoc parsing for %d .sdoc files",
                        len(sdoc_files),
                    )
                    for sdoc_file in sdoc_files:
                        self._parse_native_file(sdoc_file)
            elif json_files:
                logger.info(
                    "Using JSON export parsing for %d .json files",
                    len(json_files),
                )
                for json_file in json_files:
                    self._parse_json_file(json_file)
            else:
                logger.warning("No .sdoc or .json files found in %s", self.path)
                return {}

        # Build child relationships (reverse of parent links)
        self._build_child_relationships()

        logger.info("Parsed %d nodes with UIDs", len(self._nodes))
        return self._nodes

    # =========================================================================
    # Native StrictDoc Parsing (using StrictDoc library)
    # =========================================================================

    def _parse_native_directory(self, sdoc_dir: Path) -> bool:
        """
        Parse a directory of .sdoc files using StrictDoc's export command.
        
        This handles custom grammars by using StrictDoc's full export pipeline.
        
        Returns:
            True if successful, False if should fallback to JSON parsing.
        """
        if not _STRICTDOC_AVAILABLE:
            return False
        
        import subprocess
        import tempfile
        
        # Check if there's a config file (strictdoc.toml) or grammar file (.sgra)
        config_file = sdoc_dir / "strictdoc.toml"
        grammar_files = list(sdoc_dir.glob("*.sgra"))
        
        # If no custom grammar, try simple parsing
        if not config_file.exists() and not grammar_files:
            return False  # Fall through to simple native parsing
        
        logger.info(
            "Detected custom grammar or config, using StrictDoc export pipeline"
        )
        
        # Create a temporary directory for the JSON export
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_output = Path(temp_dir)
            
            # Build the export command
            cmd = [
                "strictdoc",
                "export",
                str(sdoc_dir),
                "--output-dir", str(temp_output),
                "--formats", "json",
            ]
            
            # Add config if present
            if config_file.exists():
                cmd.extend(["--config", str(config_file)])
            
            try:
                logger.debug("Running: %s", " ".join(cmd))
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,  # 2 minute timeout
                )
                
                if result.returncode != 0:
                    logger.warning(
                        "StrictDoc export failed: %s", 
                        result.stderr or result.stdout
                    )
                    return False
                
                # Find and parse the generated index.json
                json_dir = temp_output / "json"
                if json_dir.exists():
                    json_files = list(json_dir.glob("*.json"))
                    for json_file in json_files:
                        self._parse_json_file(json_file)
                    return True
                else:
                    logger.warning("No JSON output found in %s", temp_output)
                    return False
                    
            except subprocess.TimeoutExpired:
                logger.warning("StrictDoc export timed out")
                return False
            except FileNotFoundError:
                logger.warning("StrictDoc CLI not found in PATH")
                return False
            except Exception as e:
                logger.warning("StrictDoc export error: %s", e)
                return False

    def _parse_native_file(self, sdoc_file: Path) -> None:
        """Parse a single .sdoc file using the StrictDoc library."""
        if not _STRICTDOC_AVAILABLE:
            raise RuntimeError(
                "StrictDoc library not available. "
                "Install with: uv add strictdoc"
            )

        try:
            with open(sdoc_file, encoding="utf-8") as f:
                content = f.read()

            reader = SDReader()
            document = reader.read(content, file_path=str(sdoc_file))
            self._documents.append(document)
            self._parse_native_document(document, sdoc_file)

        except Exception as e:
            logger.error("Failed to parse %s: %s", sdoc_file, e)

    def _parse_native_document(
        self,
        document: Any,  # SDocDocument
        source_file: Path,
    ) -> None:
        """Parse all nodes from a native SDocDocument."""
        # Iterate over all nodes in the document's section_contents recursively
        self._iterate_nodes_recursive(document.section_contents, source_file)

    def _iterate_nodes_recursive(
        self,
        contents: list[Any],
        source_file: Path,
    ) -> None:
        """Recursively iterate over nodes in section_contents."""
        for node in contents:
            # Parse this node if it's a requirement-type node
            if hasattr(node, "reserved_uid"):
                self._parse_native_node(node, source_file)

            # If this node has its own section_contents (e.g., SECTION), recurse
            if hasattr(node, "section_contents") and node.section_contents:
                self._iterate_nodes_recursive(node.section_contents, source_file)

    def _parse_native_node(
        self,
        node: Any,  # NativeSDocNode
        source_file: Path,
    ) -> None:
        """Parse a single native SDocNode."""
        # Get UID
        uid = node.reserved_uid
        if not uid:
            return

        # Skip if already parsed
        if uid in self._nodes:
            logger.debug("Skipping duplicate node: %s", uid)
            return

        # Get node type
        node_type = node.node_type or "REQUIREMENT"

        # Skip TEXT and SECTION nodes without meaningful UIDs
        if node_type in ("TEXT", "SECTION") and not any(
            uid.startswith(prefix)
            for prefix in ("HAZ", "SG", "TSR", "SSR", "HSR", "TC", "EVID", "REQ")
        ):
            return

        # Extract fields
        title = node.reserved_title
        statement = node.reserved_statement if hasattr(node, "reserved_statement") else None
        rationale = node.rationale if hasattr(node, "rationale") else None
        comment = self._get_native_field_value(node, "COMMENT")

        # Extract safety-specific fields
        asil = self._get_native_field_value(node, "ASIL")
        severity = self._get_native_field_value(node, "SEVERITY")
        exposure = self._get_native_field_value(node, "EXPOSURE")
        controllability = self._get_native_field_value(node, "CONTROLLABILITY")

        # Extract parent UIDs from relations
        parent_uids = self._extract_native_parent_uids(node)

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
        logger.debug(
            "Parsed node: %s (type=%s, parents=%s)",
            uid,
            sdoc_node.get_requirement_type(),
            parent_uids,
        )

    def _get_native_field_value(self, node: Any, field_name: str) -> str | None:
        """Get a field value from a native SDocNode."""
        try:
            # Try ordered_fields_lookup first (for custom fields)
            if hasattr(node, "ordered_fields_lookup"):
                fields = node.ordered_fields_lookup.get(field_name, [])
                if fields:
                    field = fields[0]
                    if hasattr(field, "field_value"):
                        value: str = field.field_value
                        return value
                    return str(field)
            # Fall back to get_meta_field_value_by_title
            if hasattr(node, "get_meta_field_value_by_title"):
                result: str | None = node.get_meta_field_value_by_title(field_name)
                return result
        except (AttributeError, KeyError, IndexError):
            pass
        return None

    def _extract_native_parent_uids(self, node: Any) -> list[str]:
        """Extract parent UIDs from native SDocNode relations."""
        parent_uids: list[str] = []

        if not hasattr(node, "relations"):
            return parent_uids

        for relation in node.relations:
            # Check if it's a parent reference
            if hasattr(relation, "ref_type"):
                ref_type = relation.ref_type
                if ref_type in ("Parent", "Refines", "Derives"):
                    if hasattr(relation, "ref_uid") and relation.ref_uid:
                        parent_uids.append(relation.ref_uid)

        return parent_uids

    # =========================================================================
    # JSON Export Parsing (fallback mode)
    # =========================================================================

    def _parse_json_file(self, json_file: Path) -> None:
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
                self._parse_json_document_nodes(doc, json_file)
        elif isinstance(data, dict):
            if "document" in data:
                self._parse_json_document_nodes(data["document"], json_file)
            elif "NODES" in data:
                self._parse_json_all_nodes(data["NODES"], json_file)
            elif "nodes" in data:
                self._parse_json_all_nodes(data["nodes"], json_file)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "NODES" in item:
                    self._parse_json_all_nodes(item["NODES"], json_file)

    def _parse_json_document_nodes(
        self,
        doc: dict[str, Any],
        source_file: Path,
    ) -> None:
        """Parse all nodes from a JSON document using recursive walk."""
        self._documents.append(doc)
        # Support both NODES (StrictDoc standard) and sections (alternative format)
        nodes = doc.get("NODES") or doc.get("nodes") or doc.get("sections", [])
        self._parse_json_all_nodes(nodes, source_file)

    def _parse_json_all_nodes(
        self,
        nodes: list[dict[str, Any]],
        source_file: Path,
    ) -> None:
        """Parse all nodes recursively using _walk_nodes."""
        for node in _walk_nodes(nodes):
            self._parse_json_node(node, source_file)

    def _parse_json_node(self, node: dict[str, Any], source_file: Path) -> None:
        """Parse a single requirement/section node from JSON."""
        # Get UID (uppercase preferred for StrictDoc format)
        uid = node.get("UID") or node.get("uid")
        if not uid:
            return

        # Skip if already parsed (avoid duplicates)
        if uid in self._nodes:
            logger.debug("Skipping duplicate node: %s", uid)
            return

        # Get node type
        node_type = (
            node.get("TYPE")
            or node.get("type")
            or node.get("node_type")
            or node.get("_NODE_TYPE")
            or "REQUIREMENT"
        )

        # Skip TEXT and SECTION nodes without meaningful UIDs
        if node_type in ("TEXT", "SECTION") and not any(
            uid.startswith(prefix)
            for prefix in ("HAZ", "SG", "TSR", "SSR", "HSR", "TC", "EVID", "REQ")
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

        # Extract safety-specific fields (directly on node or in custom_fields)
        custom_fields = node.get("custom_fields", {})
        asil = node.get("ASIL") or node.get("asil") or custom_fields.get("ASIL")
        severity = (
            node.get("SEVERITY") or node.get("severity") or custom_fields.get("SEVERITY")
        )
        exposure = (
            node.get("EXPOSURE") or node.get("exposure") or custom_fields.get("EXPOSURE")
        )
        controllability = (
            node.get("CONTROLLABILITY")
            or node.get("controllability")
            or custom_fields.get("CONTROLLABILITY")
        )

        # Extract parent links from RELATIONS
        parent_uids = self._extract_json_parent_uids(node)

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
        logger.debug(
            "Parsed node: %s (type=%s, parents=%s)",
            uid,
            sdoc_node.get_requirement_type(),
            parent_uids,
        )

    def _extract_json_parent_uids(self, node: dict[str, Any]) -> list[str]:
        """Extract parent UIDs from JSON RELATIONS field."""
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

    # =========================================================================
    # Common Methods
    # =========================================================================

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


def parse_strictdoc_export(path: Path | str) -> dict[str, StrictDocNode]:
    """
    Convenience function to parse StrictDoc artifacts.

    Supports both native .sdoc files (when StrictDoc is installed)
    and JSON export format.

    Args:
        path: Path to StrictDoc content (directory or file).

    Returns:
        Dictionary mapping UID to StrictDocNode.
    """
    parser = StrictDocParser(Path(path))
    return parser.parse()