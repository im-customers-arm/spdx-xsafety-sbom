"""
Tests for source code scanner.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spdx_xsafety_sbom.source_scanner import SourceScanner, scan_source_markers


class TestSourceScanner:
    """Tests for SourceScanner class."""

    def test_scan_source_directory(self, fixtures_dir: Path) -> None:
        """Test scanning source directory for @sdoc markers."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir)
        links = scanner.scan()

        assert len(links) > 0
        assert "SSR-001" in links
        assert "SSR-002" in links

    def test_range_link_properties(self, fixtures_dir: Path) -> None:
        """Test RangeLink has correct properties."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir)
        links = scanner.scan()

        ssr_001_links = links.get("SSR-001", [])
        assert len(ssr_001_links) > 0

        link = ssr_001_links[0]
        assert link.uid == "SSR-001"
        assert link.line_start > 0
        assert link.line_end >= link.line_start
        assert link.file_path.name == "cam_service.c"

    def test_scan_missing_directory(self, tmp_path: Path) -> None:
        """Test error handling for missing directory."""
        scanner = SourceScanner(tmp_path / "nonexistent")

        with pytest.raises(FileNotFoundError):
            scanner.scan()

    def test_filter_by_extension(self, fixtures_dir: Path) -> None:
        """Test filtering by file extension."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir, extensions=(".py",))
        links = scanner.scan()

        # No .py files with markers in fixtures
        assert len(links) == 0

    def test_convenience_function(self, fixtures_dir: Path) -> None:
        """Test scan_source_markers convenience function."""
        source_dir = fixtures_dir / "source"
        links = scan_source_markers(source_dir)

        assert len(links) > 0
        assert "SSR-001" in links

    def test_multi_uid_marker(self, fixtures_dir: Path) -> None:
        """Test a single @sdoc marker that lists multiple UIDs."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir)
        links = scanner.scan()

        assert any(
            link.file_path.name == "cam_service.c" and link.line_start == 24
            for link in links.get("SSR-001", [])
        )
        assert any(
            link.file_path.name == "cam_service.c" and link.line_start == 24
            for link in links.get("SSR-002", [])
        )

    def test_to_spdx_range(self, fixtures_dir: Path) -> None:
        """Test RangeLink to SPDX PositionalRange conversion."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir)
        links = scanner.scan()

        link = links["SSR-001"][0]
        spdx_range = link.to_spdx_range()

        assert spdx_range["type"] == "PositionalRange"
        assert "beginPointer" in spdx_range
        assert "endPointer" in spdx_range
        assert spdx_range["beginPointer"]["lineNumber"] == link.line_start

    def test_scan_need_marker(self, fixtures_dir: Path) -> None:
        """Test scanning source files for @need markers using the shared fixture."""
        source_dir = fixtures_dir / "source"
        scanner = SourceScanner(source_dir)
        links = scanner.scan()

        fixture_file = source_dir / "cam_service_need.c"
        assert "SSR-001" in links
        assert any(link.file_path == fixture_file for link in links["SSR-001"])

    def test_scan_need_marker_with_closing_tag_style_uid(self, tmp_path: Path) -> None:
        """Test @need markers strip a leading slash from UIDs."""
        source_file = tmp_path / "cam_service_need_close.c"
        source_file.write_text(
            "// @need[/SSR-011, SSR-012]\nvoid check_close_style_uid(void) {\n    return;\n}\n",
            encoding="utf-8",
        )

        scanner = SourceScanner(tmp_path)
        links = scanner.scan()

        assert "SSR-011" in links
        assert "SSR-012" in links

    def test_scan_mixed_sdoc_and_need_markers_in_same_file(self, tmp_path: Path) -> None:
        """Test that @sdoc and @need markers in the same file are both captured.

        Guards against a regex regression where one marker type shadows the other
        when both appear in the same source file.
        """
        source_file = tmp_path / "mixed_markers.c"
        source_file.write_text(
            "// @sdoc[SSR-020]\n"
            "void sdoc_function(void) {\n"
            "    do_something();\n"
            "}\n"
            "\n"
            "// @need[SSR-021]\n"
            "void need_function(void) {\n"
            "    do_something_else();\n"
            "}\n",
            encoding="utf-8",
        )

        scanner = SourceScanner(tmp_path)
        links = scanner.scan()

        assert "SSR-020" in links, "@sdoc marker not captured in mixed file"
        assert "SSR-021" in links, "@need marker not captured in mixed file"
        assert links["SSR-020"][0].file_path == source_file
        assert links["SSR-021"][0].file_path == source_file
