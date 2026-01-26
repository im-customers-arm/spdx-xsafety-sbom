"""
Source code scanner for @sdoc requirement markers.

This module scans source files to find @sdoc[UID] markers that link
source code locations to requirements. These become SPDX testedOn
relationships with PositionalRange snippets.

Supports two modes:
1. Native mode: Uses StrictDoc library's SourceFileTraceabilityReader (tree-sitter based)
2. Regex mode: Falls back to regex-based scanning (default)

Example marker in source:
    // @sdoc[SSR-008]
    void handle_timeout(void) {
        ...
    }
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from spdx_xsafety_sbom.constants import (
    SCANNABLE_EXTENSIONS,
    SDOC_MARKER_PATTERN,
    SDOC_MULTILINE_PATTERN,
)
from spdx_xsafety_sbom.models import RangeLink

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Check if StrictDoc's source file readers are available
_STRICTDOC_SOURCE_AVAILABLE = False
try:
    from strictdoc.backend.sdoc_source_code.reader import (
        SourceFileTraceabilityReader,
    )

    _STRICTDOC_SOURCE_AVAILABLE = True
except ImportError:
    SourceFileTraceabilityReader = None  # type: ignore[misc, assignment]

# Try to import language-specific readers
_C_READER_AVAILABLE = False
_PYTHON_READER_AVAILABLE = False

try:
    from strictdoc.backend.sdoc_source_code.reader_c import (
        SourceFileTraceabilityReader_C,
    )

    _C_READER_AVAILABLE = True
except ImportError:
    SourceFileTraceabilityReader_C = None  # type: ignore[misc, assignment]

try:
    from strictdoc.backend.sdoc_source_code.reader_python import (
        SourceFileTraceabilityReader_Python,
    )

    _PYTHON_READER_AVAILABLE = True
except ImportError:
    SourceFileTraceabilityReader_Python = None  # type: ignore[misc, assignment]


def is_native_source_scanner_available() -> bool:
    """Check if native StrictDoc source scanning is available."""
    return _STRICTDOC_SOURCE_AVAILABLE


class SourceScanner:
    """
    Scanner for @sdoc markers in source code files.

    Supports both native StrictDoc parsing (using tree-sitter) and
    regex-based fallback.
    """

    def __init__(
        self,
        source_root: Path,
        extensions: tuple[str, ...] = SCANNABLE_EXTENSIONS,
        excluded_dirs: list[str] | None = None,
        *,
        prefer_native: bool = True,
    ) -> None:
        """
        Initialize the source scanner.

        Args:
            source_root: Root directory to scan
            extensions: File extensions to include
            excluded_dirs: Directory names to exclude
            prefer_native: If True, prefer native StrictDoc parsing when available
        """
        self.source_root = Path(source_root)
        self.extensions = extensions
        self.excluded_dirs = excluded_dirs or [
            ".git",
            "__pycache__",
            "node_modules",
            "venv",
            ".venv",
            "build",
            "dist",
        ]
        self.prefer_native = prefer_native and _STRICTDOC_SOURCE_AVAILABLE

        # Compile regex patterns (for fallback)
        self._single_pattern = re.compile(SDOC_MARKER_PATTERN)
        self._multi_pattern = re.compile(SDOC_MULTILINE_PATTERN)

    def scan(self) -> dict[str, list[RangeLink]]:
        """
        Scan source files for @sdoc markers.

        Uses native StrictDoc parsing when available, otherwise
        falls back to regex-based scanning.

        Returns:
            Dictionary mapping UID to list of RangeLinks.
        """
        if not self.source_root.exists():
            raise FileNotFoundError(
                f"Source root not found: {self.source_root}"
            )

        links: dict[str, list[RangeLink]] = {}

        for file_path in self._iter_source_files():
            # Choose scanning method based on preference and file type
            if self.prefer_native:
                file_links = self._scan_file_native(file_path)
            else:
                file_links = self._scan_file_regex(file_path)

            for link in file_links:
                if link.uid not in links:
                    links[link.uid] = []
                links[link.uid].append(link)

        total_links = sum(len(v) for v in links.values())
        logger.info(
            "Found %d @sdoc markers across %d UIDs",
            total_links,
            len(links),
        )

        return links

    def _iter_source_files(self) -> Iterator[Path]:
        """Iterate over scannable source files."""
        for ext in self.extensions:
            pattern = f"**/*{ext}"
            for file_path in self.source_root.glob(pattern):
                # Skip excluded directories
                if any(
                    excluded in file_path.parts
                    for excluded in self.excluded_dirs
                ):
                    continue
                yield file_path

    def _scan_file_native(self, file_path: Path) -> list[RangeLink]:
        """
        Scan a file using StrictDoc's native source traceability reader.

        Falls back to regex if native reader isn't available for this file type.

        Args:
            file_path: Path to source file.

        Returns:
            List of RangeLinks found in the file.
        """
        if not _STRICTDOC_SOURCE_AVAILABLE:
            return self._scan_file_regex(file_path)

        # Get appropriate reader for file extension
        reader = self._get_native_reader(file_path)
        if reader is None:
            # Fall back to regex for unsupported file types
            return self._scan_file_regex(file_path)

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Use the reader to get traceability info
            traceability_info = reader.read(content)

            return self._convert_traceability_to_links(
                traceability_info, file_path, content
            )

        except Exception as e:
            logger.warning(
                "Native parsing failed for %s, falling back to regex: %s",
                file_path,
                e,
            )
            return self._scan_file_regex(file_path)

    def _get_native_reader(self, file_path: Path) -> Any | None:
        """Get the appropriate StrictDoc reader for a file type."""
        suffix = file_path.suffix.lower()

        # C/C++ files
        if suffix in (".c", ".cpp", ".h", ".hpp", ".cc", ".cxx"):
            if _C_READER_AVAILABLE and SourceFileTraceabilityReader_C:
                return SourceFileTraceabilityReader_C()
            return None

        # Python files
        if suffix == ".py":
            if _PYTHON_READER_AVAILABLE and SourceFileTraceabilityReader_Python:
                return SourceFileTraceabilityReader_Python()
            return None

        # For other types, try the generic reader if available
        if _STRICTDOC_SOURCE_AVAILABLE and SourceFileTraceabilityReader:
            # The generic reader may need file type hints
            return None  # Fall back to regex for unknown types

        return None

    def _convert_traceability_to_links(
        self,
        traceability_info: Any,
        file_path: Path,
        content: str,
    ) -> list[RangeLink]:
        """Convert StrictDoc traceability info to RangeLinks."""
        links: list[RangeLink] = []
        lines = content.split("\n")

        # Extract markers from traceability info
        if not hasattr(traceability_info, "markers"):
            return links

        for marker in traceability_info.markers:
            # Get UID from marker
            uid = None
            if hasattr(marker, "reqs") and marker.reqs:
                for req in marker.reqs:
                    if hasattr(req, "uid"):
                        uid = req.uid
                    elif isinstance(req, str):
                        uid = req
                    if uid:
                        break

            if not uid:
                continue

            # Get line range from marker
            line_start = 1
            line_end = len(lines)

            if hasattr(marker, "ng_source_line_begin"):
                line_start = marker.ng_source_line_begin
            if hasattr(marker, "ng_source_line_end"):
                line_end = marker.ng_source_line_end

            # Extract snippet
            snippet_lines = lines[line_start - 1 : min(line_end, line_start + 4)]
            snippet = "\n".join(snippet_lines).strip()

            link = RangeLink(
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                uid=uid,
                snippet=snippet[:500] if len(snippet) > 500 else snippet,
            )
            links.append(link)
            logger.debug(
                "Found @sdoc[%s] at %s:%d-%d (native)",
                uid,
                file_path.name,
                line_start,
                line_end,
            )

        return links

    def _scan_file_regex(self, file_path: Path) -> list[RangeLink]:
        """
        Scan a single file for @sdoc markers using regex.

        Args:
            file_path: Path to source file.

        Returns:
            List of RangeLinks found in the file.
        """
        links: list[RangeLink] = []

        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            logger.warning("Could not read %s: %s", file_path, e)
            return []

        for line_num, line in enumerate(lines, start=1):
            # Find all @sdoc markers on this line
            matches = self._single_pattern.findall(line)

            for uid in matches:
                # Determine the range (marker line + following code block)
                line_end = self._find_block_end(lines, line_num - 1)

                # Extract code snippet (up to 5 lines)
                snippet_lines = lines[line_num - 1 : min(line_end, line_num + 4)]
                snippet = "".join(snippet_lines).strip()

                link = RangeLink(
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_end,
                    uid=uid,
                    snippet=snippet[:500] if len(snippet) > 500 else snippet,
                )
                links.append(link)
                logger.debug(
                    "Found @sdoc[%s] at %s:%d-%d",
                    uid,
                    file_path.name,
                    line_num,
                    line_end,
                )

        return links

    def _find_block_end(self, lines: list[str], start_idx: int) -> int:
        """
        Find the end of a code block following a marker.

        Looks for function/block boundaries using brace counting
        or significant whitespace changes.

        Args:
            lines: All lines in the file.
            start_idx: Index of the marker line.

        Returns:
            Line number (1-indexed) of block end.
        """
        if start_idx >= len(lines):
            return start_idx + 1

        # Simple heuristic: find next blank line or end of brace block
        brace_count = 0
        in_block = False

        for i in range(start_idx, min(start_idx + 100, len(lines))):
            line = lines[i]

            # Count braces
            brace_count += line.count("{") - line.count("}")

            if "{" in line:
                in_block = True

            # End conditions
            if in_block and brace_count <= 0:
                return i + 1  # Convert to 1-indexed

            # For languages without braces, use blank line
            if not in_block and i > start_idx and not line.strip():
                return i  # Previous line was the end

        # Default: return start + 10 lines or end of file
        return min(start_idx + 11, len(lines))

    def get_files_for_uid(self, uid: str) -> list[Path]:
        """
        Get all source files that reference a specific UID.

        Args:
            uid: Requirement UID to search for.

        Returns:
            List of file paths.
        """
        links = self.scan()
        if uid in links:
            return [link.file_path for link in links[uid]]
        return []


def scan_source_markers(
    source_root: Path | str,
    extensions: tuple[str, ...] | None = None,
    excluded_dirs: list[str] | None = None,
) -> dict[str, list[RangeLink]]:
    """
    Convenience function to scan for @sdoc markers.

    Args:
        source_root: Root directory to scan.
        extensions: File extensions to include.
        excluded_dirs: Directories to exclude.

    Returns:
        Dictionary mapping UID to list of RangeLinks.
    """
    scanner = SourceScanner(
        Path(source_root),
        extensions=extensions or SCANNABLE_EXTENSIONS,
        excluded_dirs=excluded_dirs,
    )
    return scanner.scan()
