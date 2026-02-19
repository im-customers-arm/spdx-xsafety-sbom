"""
Source code scanner for @sdoc requirement markers.

This module scans source files to find @sdoc[UID] markers that link
source code locations to requirements. These become SPDX testedOn
relationships with PositionalRange snippets.

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

from spdx_xsafety_sbom.constants import SCANNABLE_EXTENSIONS
from spdx_xsafety_sbom.models import RangeLink

logger = logging.getLogger(__name__)

# Regex pattern for @sdoc[...] markers (supports multiple UIDs, closing tags)
SDOC_MARKER_PATTERN = re.compile(r"@sdoc\[([^\]]+)\]")


class SourceScanner:
    """
    Scanner for @sdoc markers in source code files.

    Scans source files for @sdoc[UID] markers and extracts
    line ranges and code snippets for SPDX traceability.
    """

    def __init__(
        self,
        source_root: Path,
        extensions: tuple[str, ...] = SCANNABLE_EXTENSIONS,
        excluded_dirs: list[str] | None = None,
    ) -> None:
        """
        Initialize the source scanner.

        Args:
            source_root: Root directory to scan
            extensions: File extensions to include
            excluded_dirs: Directory names to exclude
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

    def scan(self) -> dict[str, list[RangeLink]]:
        """
        Scan source files for @sdoc markers.

        Returns:
            Dictionary mapping UID to list of RangeLinks.
        """
        if not self.source_root.exists():
            raise FileNotFoundError(f"Source root not found: {self.source_root}")

        links: dict[str, list[RangeLink]] = {}

        for file_path in self._iter_source_files():
            file_links = self._scan_file(file_path)

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

    def _iter_source_files(self):
        """Iterate over scannable source files."""
        for ext in self.extensions:
            pattern = f"**/*{ext}"
            for file_path in self.source_root.glob(pattern):
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in self.excluded_dirs):
                    continue
                yield file_path

    def _scan_file(self, file_path: Path) -> list[RangeLink]:
        """
        Scan a single file for @sdoc markers.

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
            matches = SDOC_MARKER_PATTERN.findall(line)

            for match in matches:
                raw_uids = [part.strip() for part in match.split(",")]
                uids = [uid.lstrip("/") for uid in raw_uids if uid.strip()]
                if not uids:
                    continue

                # Determine the range (marker line + following code block)
                line_end = self._find_block_end(lines, line_num - 1)

                # Extract code snippet (up to 5 lines)
                snippet_lines = lines[line_num - 1 : min(line_end, line_num + 4)]
                snippet = "".join(snippet_lines).strip()

                for uid in uids:
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
