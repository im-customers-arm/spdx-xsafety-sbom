"""
Tests for CLI behavior.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from spdx_xsafety_sbom.cli import auto_detect_source_root, main
from spdx_xsafety_sbom.models import GenerationResult


class TestCli:
    """Tests for CLI commands related to generation."""

    def test_generate_help_includes_new_input_options(self) -> None:
        """Test generate --help documents the input path and input format."""
        runner = CliRunner()

        result = runner.invoke(main, ["generate", "--help"])

        assert result.exit_code == 0
        assert "INPUT_PATH" in result.output
        assert "--input-format" in result.output
        assert "sphinx-needs" in result.output

    def test_generate_accepts_sphinxneeds_file_and_passes_input_format(
        self,
        monkeypatch,
        sample_sphinxneeds_export: Path,
        tmp_output: Path,
    ) -> None:
        """Test generate command accepts needs.json and forwards the explicit format."""
        captured: dict[str, object] = {}

        def fake_generate_design_sbom(**kwargs):
            captured.update(kwargs)
            return GenerationResult(
                success=True,
                output_path=Path(kwargs["output_path"]),
                element_count=5,
                relationship_count=3,
                generation_time=0.01,
            )

        monkeypatch.setattr("spdx_xsafety_sbom.cli.generate_design_sbom", fake_generate_design_sbom)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "generate",
                str(sample_sphinxneeds_export),
                "--input-format",
                "sphinx-needs",
                "--no-source-scan",
                "--no-validate",
                "-o",
                str(tmp_output),
            ],
        )

        assert result.exit_code == 0
        assert captured["strictdoc_export_path"] == sample_sphinxneeds_export
        assert captured["input_format"] == "sphinx-needs"
        assert captured["scan_source_markers"] is False
        assert captured["validate_output"] is False
        assert "Input Format" in result.output

    def test_generate_rejects_unsupported_input_format(
        self, sample_sphinxneeds_export: Path, tmp_output: Path
    ) -> None:
        """Test the CLI rejects unsupported input_format values before command execution."""
        runner = CliRunner()

        result = runner.invoke(
            main,
            [
                "generate",
                str(sample_sphinxneeds_export),
                "--input-format",
                "markdown",
                "-o",
                str(tmp_output),
            ],
        )

        assert result.exit_code == 2
        assert "Invalid value for '--input-format'" in result.output
        assert "sphinx-needs" in result.output

    def test_auto_detect_source_root_accepts_file_input(self, tmp_path: Path) -> None:
        """Test source-root auto-detection works when the input path is a file."""
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / ".git").mkdir()
        needs_path = repo_root / "build" / "needs.json"
        needs_path.parent.mkdir()
        needs_path.write_text("{}", encoding="utf-8")

        assert auto_detect_source_root(needs_path) == repo_root
