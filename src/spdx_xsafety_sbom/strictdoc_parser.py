"""
StrictDoc parser module.

This module provides parsing of StrictDoc artifacts to extract:
- Requirements with UIDs
- Safety metadata (ASIL, HARA ratings)
- Traceability links (parent/child relationships)
- Document structure

Uses StrictDoc library directly for native .sdoc file parsing.
Requires StrictDoc to be installed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom.models import StrictDocNode

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# StrictDoc library is required
try:
    from strictdoc.backend.sdoc.reader import SDReader

    _STRICTDOC_AVAILABLE = True
except ImportError as e:
    raise ImportError(
        "StrictDoc library is required for native parsing. "
        "Install with: uv add strictdoc"
    ) from e


def is_strictdoc_available() -> bool:
    """Check if StrictDoc library is available for native parsing."""
    return _STRICTDOC_AVAILABLE


class StrictDocParser:
    """
    Parser for StrictDoc .sdoc files using native StrictDoc library.

    Parses .sdoc files directly using StrictDoc's SDReader for
    requirements extraction and traceability analysis.
    """

    def __init__(
        self,
        path: Path,
    ) -> None:
        """
        Initialize the StrictDoc parser.

        Args:
            path: Path to StrictDoc content. Can be:
                - A directory containing .sdoc files
                - A single .sdoc file
        """
        self.path = Path(path)
        # Legacy alias for backward compatibility
        self.export_path = self.path
        self._nodes: dict[str, StrictDocNode] = {}
        self._documents: list[Any] = []

    def parse(self) -> dict[str, StrictDocNode]:
        """
        Parse StrictDoc .sdoc files.

        Uses native SDReader for simple projects, but falls back to
        running `strictdoc export` for projects with custom grammars.

        Returns:
            Dictionary mapping UID to StrictDocNode objects.
        """
        if not self.path.exists():
            raise FileNotFoundError(f"StrictDoc path not found: {self.path}")

        if self.path.is_file():
            if self.path.suffix == ".sdoc":
                self._parse_native_file(self.path)
            else:
                raise ValueError(
                    f"Unsupported file type: {self.path.suffix}. "
                    "Only .sdoc files are supported."
                )
        else:
            # Directory: check for custom grammars
            sgra_files = list(self.path.glob("**/*.sgra"))
            sdoc_files = list(self.path.glob("**/*.sdoc"))

            if not sdoc_files:
                logger.warning("No .sdoc files found in %s", self.path)
                return {}

            if sgra_files:
                # Custom grammars detected - use export-based parsing
                logger.info(
                    "Custom grammar files detected (%d .sgra files). "
                    "Using strictdoc export for parsing.",
                    len(sgra_files),
                )
                self._parse_via_export()
            else:
                # Standard grammars - use native parsing
                logger.info(
                    "Using native StrictDoc parsing for %d .sdoc files",
                    len(sdoc_files),
                )
                for sdoc_file in sdoc_files:
                    self._parse_native_file(sdoc_file)

        # Build child relationships (reverse of parent links)
        self._build_child_relationships()

        logger.info("Parsed %d nodes with UIDs", len(self._nodes))
        return self._nodes

    # =========================================================================
    # Export-based Parsing (for projects with custom grammars)
    # =========================================================================

    def _parse_via_export(self) -> None:
        """
        Parse StrictDoc project by running `strictdoc export --formats json`.

        This is required for projects with custom grammars (.sgra files)
        because the SDReader doesn't handle IMPORT_FROM_FILE directives.
        """
        import json
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_output = Path(temp_dir) / "export"

            # Run strictdoc export from the source directory
            # This ensures grammar files are resolved relative to the .sdoc files
            #
            # Use the strictdoc CLI from the current Python environment
            import os
            import shutil
            import sys

            # Find strictdoc in the current environment (venv or system)
            # Check if we're in a venv and use its Scripts directory
            strictdoc_cmd = None
            if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                # We're in a virtual environment
                if os.name == 'nt':  # Windows
                    venv_strictdoc = Path(sys.prefix) / "Scripts" / "strictdoc.exe"
                else:  # Linux/Mac
                    venv_strictdoc = Path(sys.prefix) / "bin" / "strictdoc"
                
                if venv_strictdoc.exists():
                    strictdoc_cmd = str(venv_strictdoc)
            
            # Fallback to shutil.which
            if not strictdoc_cmd:
                strictdoc_cmd = shutil.which("strictdoc")
            
            if not strictdoc_cmd:
                raise RuntimeError(
                    "StrictDoc CLI not found. Install with: uv add strictdoc"
                )

            logger.debug("Using StrictDoc at: %s", strictdoc_cmd)

            cmd = [
                strictdoc_cmd,
                "export",
                ".",  # Export current directory
                "--output-dir",
                str(temp_output),
                "--formats",
                "json",
            ]

            try:
                # Use current environment - python -m strictdoc will use
                # the correct StrictDoc version from this environment
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                    cwd=str(self.path),  # Run from the StrictDoc directory
                )

                if result.returncode != 0:
                    logger.error("StrictDoc export failed: %s", result.stderr)
                    logger.error("stdout: %s", result.stdout)
                    raise RuntimeError(
                        f"StrictDoc export failed with code {result.returncode}: "
                        f"{result.stderr or result.stdout}"
                    )

            except subprocess.TimeoutExpired as err:
                logger.error("StrictDoc export timed out")
                raise RuntimeError("StrictDoc export timed out after 120 seconds") from err
            except FileNotFoundError as err:
                logger.error("StrictDoc CLI not found")
                raise RuntimeError(
                    "StrictDoc CLI not found. Install with: uv add strictdoc"
                ) from err

            # Find and parse the JSON output
            json_file = temp_output / "json" / "index.json"
            if not json_file.exists():
                raise RuntimeError(f"JSON export not found at {json_file}")

            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)

            # Parse the JSON structure
            self._parse_json_export(data)

    def _parse_json_export(self, data: dict) -> None:
        """
        Parse the JSON export from StrictDoc.

        Args:
            data: Parsed JSON data from index.json export.
        """
        documents = data.get("DOCUMENTS", [])
        for doc in documents:
            doc_title = doc.get("TITLE", "Unknown")
            self._parse_json_document(doc, doc_title)

    def _parse_json_document(self, doc: dict, doc_title: str) -> None:
        """Parse a single document from JSON export."""
        # Parse NODES (flat list of all nodes)
        nodes = doc.get("NODES", [])
        self._walk_json_nodes(nodes, doc_title)

    def _walk_json_nodes(self, nodes: list, doc_title: str) -> None:
        """Recursively walk through JSON nodes."""
        for node in nodes:
            node_type = node.get("NODE_TYPE", "")

            # Skip structural nodes
            if node_type in ("SECTION", "DOCUMENT"):
                # Recurse into children
                children = node.get("NODES", [])
                if children:
                    self._walk_json_nodes(children, doc_title)
                continue

            # Parse requirement-type nodes
            uid = node.get("UID")
            if uid:
                self._parse_json_node(node)

            # Recurse into children
            children = node.get("NODES", [])
            if children:
                self._walk_json_nodes(children, doc_title)

    def _parse_json_node(self, node: dict) -> None:
        """Parse a single node from JSON export."""
        uid = node.get("UID")
        if not uid or uid in self._nodes:
            return

        node_type = node.get("NODE_TYPE", "REQUIREMENT")
        title = node.get("TITLE")
        statement = node.get("STATEMENT")
        rationale = node.get("RATIONALE")
        comment = node.get("COMMENT")

        # Safety metadata
        asil = node.get("ASIL")
        severity = node.get("SEVERITY")
        exposure = node.get("EXPOSURE")
        controllability = node.get("CONTROLLABILITY")

        # Extract parent UIDs from RELATIONS
        parent_uids = self._extract_json_parent_uids(node)

        # Create the node
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
            document_path=None,  # Not available from JSON
        )

        self._nodes[uid] = sdoc_node
        logger.debug(
            "Parsed JSON node: %s (type=%s, parents=%s)",
            uid,
            sdoc_node.get_requirement_type(),
            parent_uids,
        )

    def _extract_json_parent_uids(self, node: dict) -> list[str]:
        """Extract parent UIDs from JSON node relations."""
        parent_uids: list[str] = []
        relations = node.get("RELATIONS", [])

        for relation in relations:
            rel_type = relation.get("TYPE", "")
            if rel_type in ("Parent", "Refines", "Derives"):
                ref_uid = relation.get("VALUE")
                if ref_uid:
                    parent_uids.append(ref_uid)

        return parent_uids

    # =========================================================================
    # Native StrictDoc Parsing (using StrictDoc library)
    # =========================================================================

    def _inline_grammar_imports(self, content: str, base_path: Path) -> str:
        """
        Inline IMPORT_FROM_FILE grammar references.

        StrictDoc's SDReader doesn't resolve IMPORT_FROM_FILE directives,
        so we need to inline the grammar content before parsing.

        Args:
            content: The .sdoc file content.
            base_path: Base path for resolving relative grammar file paths.

        Returns:
            Content with grammar file inlined.
        """
        import re

        pattern = r"\[GRAMMAR\]\nIMPORT_FROM_FILE:\s*(\S+)"
        match = re.search(pattern, content)
        if match:
            grammar_filename = match.group(1)
            grammar_path = base_path / grammar_filename
            if grammar_path.exists():
                with open(grammar_path, encoding="utf-8") as f:
                    grammar_text = f.read()
                # Replace the import directive with the actual grammar content
                content = re.sub(pattern, grammar_text, content)
                logger.debug("Inlined grammar from %s", grammar_path)
        return content

    def _parse_native_file(self, sdoc_file: Path) -> None:
        """Parse a single .sdoc file using the StrictDoc library."""
        try:
            with open(sdoc_file, encoding="utf-8") as f:
                content = f.read()

            # Inline any grammar imports
            content = self._inline_grammar_imports(content, sdoc_file.parent)

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
        statement = (
            node.reserved_statement if hasattr(node, "reserved_statement") else None
        )
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
                if (
                    ref_type in ("Parent", "Refines", "Derives")
                    and hasattr(relation, "ref_uid")
                    and relation.ref_uid
                ):
                    parent_uids.append(relation.ref_uid)

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
        return [node for node in self._nodes.values() if node.uid.startswith(prefix)]

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
    Convenience function to parse StrictDoc .sdoc files.

    Uses StrictDoc library for native parsing.
    Requires StrictDoc to be installed.

    Args:
        path: Path to StrictDoc content (directory or .sdoc file).

    Returns:
        Dictionary mapping UID to StrictDocNode.
    """
    parser = StrictDocParser(Path(path))
    return parser.parse()
