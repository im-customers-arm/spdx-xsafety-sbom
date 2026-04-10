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
    from strictdoc.backend.sdoc.reader import SDReader  # type: ignore[import-untyped]

    _STRICTDOC_AVAILABLE = True

    # Import TextX exceptions for better error handling
    try:
        from textx.exceptions import TextXSyntaxError  # type: ignore[import-untyped]

        _TEXTX_AVAILABLE = True
    except ImportError:
        _TEXTX_AVAILABLE = False
        TextXSyntaxError = Exception  # Fallback
except ImportError as e:
    raise ImportError(
        "StrictDoc library is required for native parsing. Install with: uv add strictdoc"
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

    def _format_syntax_error(self, error: Exception, file_path: Path) -> str:
        """
        Format a StrictDoc syntax error with helpful guidance.

        Args:
            error: The exception that was raised.
            file_path: Path to the file being parsed.

        Returns:
            Formatted error message with guidance.
        """
        error_msg = str(error)

        # Extract line and column info if available
        import re

        line_match = re.search(r":(\d+):(\d+):", error_msg)
        if line_match:
            line_num = int(line_match.group(1))
            col_num = int(line_match.group(2))

            # Try to show the problematic line
            try:
                with open(file_path, encoding="utf-8") as f:
                    lines = f.readlines()
                    if 0 <= line_num - 1 < len(lines):
                        problem_line = lines[line_num - 1].rstrip()

                        msg_parts = [
                            f"\n{'=' * 70}",
                            f"StrictDoc Syntax Error in: {file_path}",
                            f"{'=' * 70}",
                            f"Line {line_num}, Column {col_num}:",
                            f"  {problem_line}",
                            f"  {' ' * (col_num - 1)}^",
                            "",
                            f"Error: {error_msg}",
                            "",
                            "Common fixes:",
                            "  1. Check for missing colons after field names (e.g., 'FREETEXT:' not 'FREETEXT]')",
                            "  2. Ensure proper field name format: UPPERCASE with optional underscores",
                            "  3. Verify closing brackets/tags are properly matched",
                            "  4. Check for invalid characters in field names",
                            "",
                            "Valid field names: UID, TITLE, STATEMENT, FREETEXT, ASIL, REFS, etc.",
                            "",
                            "For more details, run:",
                            f"  uv run strictdoc --debug export {file_path.parent}",
                            f"{'=' * 70}\n",
                        ]
                        return "\n".join(msg_parts)
            except Exception:
                pass  # Fall through to basic message

        # Fallback message
        return (
            f"\nStrictDoc parsing error in {file_path}:\n"
            f"  {error_msg}\n\n"
            f"Common causes:\n"
            f"  - Malformed field syntax (missing colons, invalid brackets)\n"
            f"  - Invalid field names (must be UPPERCASE)\n"
            f"  - Unclosed tags or mismatched delimiters\n\n"
            f"Run 'uv run strictdoc --debug export {file_path.parent}' for details.\n"
        )

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

        # Reset state for idempotent parsing
        self._nodes = {}
        self._documents = []

        if self.path.is_file():
            if self.path.suffix == ".sdoc":
                # Check if parent directory has custom grammars
                parent_dir = self.path.parent
                sgra_files = list(parent_dir.glob("**/*.sgra"))

                if sgra_files:
                    # Custom grammars detected - must use export-based parsing
                    # Parse the entire parent directory instead of just this file
                    logger.info(
                        "Custom grammar files detected in %s. "
                        "Using export-based parsing for entire directory.",
                        parent_dir,
                    )
                    # Temporarily switch to directory mode
                    original_path = self.path
                    self.path = parent_dir
                    try:
                        self._parse_via_export()
                    finally:
                        self.path = original_path
                else:
                    # No custom grammars - safe to use native parsing
                    self._parse_native_file(self.path)
            else:
                raise ValueError(
                    f"Unsupported file type: {self.path.suffix}. Only .sdoc files are supported."
                )
        else:
            # Directory: check for custom grammars
            sgra_files = list(self.path.glob("**/*.sgra"))
            sdoc_files = list(self.path.glob("**/*.sdoc"))

            if not sdoc_files:
                error_msg = (
                    f"\nNo StrictDoc (.sdoc) files found in: {self.path}\n\n"
                    f"Please ensure:\n"
                    f"  1. The directory contains .sdoc files\n"
                    f"  2. Files have the .sdoc extension (not .txt or .md)\n"
                    f"  3. The path is correct: {self.path.absolute()}\n\n"
                    f"Directory contents:\n"
                )
                # Show first few files to help user
                try:
                    all_files = list(self.path.glob("**/*"))[:10]
                    if all_files:
                        error_msg += "  " + "\n  ".join(
                            str(f.relative_to(self.path)) for f in all_files if f.is_file()
                        )
                    else:
                        error_msg += "  (directory is empty)"
                except Exception:
                    error_msg += "  (unable to list files)"

                logger.warning(error_msg)
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
            if hasattr(sys, "real_prefix") or (
                hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
            ):
                # We're in a virtual environment
                if os.name == "nt":  # Windows
                    venv_strictdoc = Path(sys.prefix) / "Scripts" / "strictdoc.exe"
                else:  # Linux/Mac
                    venv_strictdoc = Path(sys.prefix) / "bin" / "strictdoc"

                if venv_strictdoc.exists():
                    strictdoc_cmd = str(venv_strictdoc)

            # Fallback to shutil.which
            if not strictdoc_cmd:
                strictdoc_cmd = shutil.which("strictdoc")

            if not strictdoc_cmd:
                raise RuntimeError("StrictDoc CLI not found. Install with: uv add strictdoc")

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
                    error_output = result.stderr or result.stdout or "Unknown error"

                    # Check for common error patterns
                    if "TextXSyntaxError" in error_output:
                        error_msg = (
                            f"\n{'=' * 70}\n"
                            f"StrictDoc Export Failed: Syntax Error Detected\n"
                            f"{'=' * 70}\n"
                            f"{error_output}\n\n"
                            f"This indicates a syntax error in one of your .sdoc files.\n\n"
                            f"Common fixes:\n"
                            f"  1. Check field names have colons: 'FREETEXT:' not 'FREETEXT]'\n"
                            f"  2. Ensure field names are UPPERCASE: 'UID' not 'uid'\n"
                            f"  3. Verify brackets and tags are properly matched\n"
                            f"  4. Check for special characters in unexpected places\n\n"
                            f"To find the exact error:\n"
                            f"  cd {self.path}\n"
                            f"  uv run strictdoc --debug export .\n"
                            f"{'=' * 70}\n"
                        )
                    elif "Could not parse file" in error_output:
                        # Extract filename if possible
                        import re

                        file_match = re.search(r"Could not parse file: ([^\n]+)", error_output)
                        problem_file = file_match.group(1) if file_match else "unknown"
                        error_msg = (
                            f"\n{'=' * 70}\n"
                            f"StrictDoc Export Failed: Parse Error\n"
                            f"{'=' * 70}\n"
                            f"Problem file: {problem_file}\n\n"
                            f"{error_output}\n\n"
                            f"Troubleshooting steps:\n"
                            f"  1. Open the file and check for syntax errors\n"
                            f"  2. Validate against StrictDoc documentation\n"
                            f"  3. Look for missing or extra brackets/tags\n"
                            f"  4. Check for invalid field names\n\n"
                            f"For debugging:\n"
                            f"  uv run strictdoc --debug export {self.path}\n"
                            f"{'=' * 70}\n"
                        )
                    else:
                        error_msg = (
                            f"\nStrictDoc export failed with exit code {result.returncode}\n"
                            f"{'=' * 70}\n"
                            f"{error_output}\n"
                            f"{'=' * 70}\n\n"
                            f"Working directory: {self.path}\n\n"
                            f"Try running manually for more details:\n"
                            f"  cd {self.path}\n"
                            f"  uv run strictdoc --debug export .\n"
                        )

                    logger.error(error_msg)
                    raise RuntimeError(error_msg)

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

    def _parse_json_export(self, data: dict[str, Any]) -> None:
        """
        Parse the JSON export from StrictDoc.

        Args:
            data: Parsed JSON data from index.json export.
        """
        documents = data.get("DOCUMENTS", [])
        for doc in documents:
            doc_title = doc.get("TITLE", "Unknown")
            self._parse_json_document(doc, doc_title)

    def _parse_json_document(self, doc: dict[str, Any], doc_title: str) -> None:
        """Parse a single document from JSON export."""
        # Parse NODES (flat list of all nodes)
        nodes = doc.get("NODES", [])
        self._walk_json_nodes(nodes, doc_title)

    def _walk_json_nodes(self, nodes: list[dict[str, Any]], doc_title: str) -> None:
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

    def _parse_json_node(self, node: dict[str, Any]) -> None:
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
        evidence_artifact_id = node.get("ARTIFACT_ID")
        evidence_timestamp_utc = node.get("TIMESTAMP_UTC")
        evidence_hash = node.get("HASH")

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
            evidence_artifact_id=evidence_artifact_id,
            evidence_timestamp_utc=evidence_timestamp_utc,
            evidence_hash=evidence_hash,
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

    def _extract_json_parent_uids(self, node: dict[str, Any]) -> list[str]:
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

        Note: Custom grammars (.sgra files) are better handled by the
        export-based parsing approach. This method is for simple cases only.

        Args:
            content: The .sdoc file content.
            base_path: Base path for resolving relative grammar file paths.

        Returns:
            Content with grammar file inlined, or raises ValueError if
            custom grammar is detected (should use export instead).
        """
        import re

        # Check for IMPORT_FROM_FILE directive
        pattern = r"\[GRAMMAR\]\s*\nIMPORT_FROM_FILE:\s*(\S+)"
        match = re.search(pattern, content)
        if match:
            grammar_filename = match.group(1)
            grammar_path = base_path / grammar_filename

            # If the grammar file exists and is a .sgra (custom grammar),
            # raise an error indicating export-based parsing is needed
            if grammar_path.exists() and grammar_path.suffix == ".sgra":
                raise ValueError(
                    f"\n{'=' * 70}\n"
                    f"Custom Grammar Detected: {grammar_filename}\n"
                    f"{'=' * 70}\n"
                    f"This file uses a custom StrictDoc grammar (.sgra file).\n"
                    f"Custom grammars require export-based parsing.\n\n"
                    f"To validate files with custom grammars:\n"
                    f"  1. Validate the entire directory (not individual files):\n"
                    f"     uv run python scripts/validate_sdoc_files.py {base_path}\n\n"
                    f"  2. Or use StrictDoc directly:\n"
                    f"     uv run strictdoc export {base_path}\n\n"
                    f"The parser will automatically use export-based parsing\n"
                    f"when validating a directory containing .sgra files.\n"
                    f"{'=' * 70}\n"
                )

            # For non-custom grammars, inline them
            if grammar_path.exists():
                with open(grammar_path, encoding="utf-8") as f:
                    grammar_text = f.read()
                # Replace the entire [GRAMMAR] block with the inlined grammar
                content = re.sub(pattern, f"[GRAMMAR]\n{grammar_text}", content)
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

        except FileNotFoundError as e:
            error_msg = (
                f"\nStrictDoc file not found: {sdoc_file}\n"
                f"Please verify the file path is correct.\n"
            )
            logger.error(error_msg)
            raise FileNotFoundError(error_msg) from e
        except UnicodeDecodeError as e:
            error_msg = (
                f"\nEncoding error in StrictDoc file: {sdoc_file}\n"
                f"The file appears to have invalid UTF-8 encoding.\n"
                f"Try saving the file with UTF-8 encoding.\n"
            )
            logger.error(error_msg)
            raise ValueError(error_msg) from e
        except Exception as e:
            # Check if it's a TextX syntax error
            if _TEXTX_AVAILABLE and isinstance(e, TextXSyntaxError):
                formatted_error = self._format_syntax_error(e, sdoc_file)
                logger.error(formatted_error)
                raise ValueError(formatted_error) from e
            elif "TextXSyntaxError" in type(e).__name__:
                # TextX error but we don't have the class imported
                formatted_error = self._format_syntax_error(e, sdoc_file)
                logger.error(formatted_error)
                raise ValueError(formatted_error) from e
            else:
                # Other parsing errors
                error_msg = (
                    f"\nFailed to parse StrictDoc file: {sdoc_file}\n"
                    f"Error: {e}\n\n"
                    f"Possible causes:\n"
                    f"  - Invalid StrictDoc syntax\n"
                    f"  - Unsupported grammar features\n"
                    f"  - File corruption\n\n"
                    f"For detailed debugging:\n"
                    f"  uv run strictdoc --debug export {sdoc_file.parent}\n"
                )
                logger.error(error_msg)
                raise ValueError(error_msg) from e

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
        evidence_artifact_id = self._get_native_field_value(node, "ARTIFACT_ID")
        evidence_timestamp_utc = self._get_native_field_value(node, "TIMESTAMP_UTC")
        evidence_hash = self._get_native_field_value(node, "HASH")

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
            evidence_artifact_id=evidence_artifact_id,
            evidence_timestamp_utc=evidence_timestamp_utc,
            evidence_hash=evidence_hash,
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
