"""
Click-based CLI for SPDX xSafety SBOM generator.

Commands:
- generate: Generate SPDX 3.0.1 Design SBOM from StrictDoc export
- validate: Validate an existing SBOM against SPDX/xSafety schemas
- version: Display version information
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from spdx_xsafety_sbom import __version__
from spdx_xsafety_sbom.generator import generate_design_sbom

if TYPE_CHECKING:
    pass

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.version_option(version=__version__, prog_name="spdx-xsafety-sbom")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """
    SPDX xSafety SBOM Generator

    Generate SPDX 3.0.1 Design SBOMs with xSafety extension
    from StrictDoc requirements and source code.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@main.command()
@click.argument(
    "strictdoc_export",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path("design-sbom.json"),
    help="Output file path [default: design-sbom.json]",
)
@click.option(
    "-s",
    "--source-root",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Root directory for source code scanning",
)
@click.option(
    "--prefix",
    type=str,
    default="urn:spdx:example:",
    help="SPDX ID prefix [default: urn:spdx:example:]",
)
@click.option(
    "--name",
    type=str,
    default="design-sbom",
    help="Document name [default: design-sbom]",
)
@click.option(
    "--org",
    type=str,
    help="Organization name for CreationInfo",
)
@click.option(
    "--no-source-scan",
    is_flag=True,
    help="Disable @sdoc marker scanning",
)
@click.option(
    "--no-validate",
    is_flag=True,
    help="Disable output validation",
)
@click.pass_context
def generate(
    ctx: click.Context,
    strictdoc_export: Path,
    output: Path,
    source_root: Path | None,
    prefix: str,
    name: str,
    org: str | None,
    no_source_scan: bool,
    no_validate: bool,
) -> None:
    """
    Generate an SPDX 3.0.1 Design SBOM from StrictDoc export.

    STRICTDOC_EXPORT is the path to the StrictDoc JSON export directory
    (typically build/strictdoc-json/).

    Example:

        spdx-xsafety-sbom generate build/strictdoc-json -o design-sbom.json -s ./

    """
    console.print(
        Panel.fit(
            f"[bold blue]SPDX xSafety SBOM Generator v{__version__}[/]",
            border_style="blue",
        )
    )

    # Show configuration
    config_table = Table(title="Configuration", show_header=False)
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value")
    config_table.add_row("StrictDoc Export", str(strictdoc_export))
    config_table.add_row("Output", str(output))
    config_table.add_row("Source Root", str(source_root) if source_root else "None")
    config_table.add_row("SPDX ID Prefix", prefix)
    config_table.add_row("Document Name", name)
    config_table.add_row("Organization", org or "None")
    config_table.add_row("Source Scanning", "Disabled" if no_source_scan else "Enabled")
    config_table.add_row("Validation", "Disabled" if no_validate else "Enabled")
    console.print(config_table)
    console.print()

    # Generate SBOM
    with console.status("[bold green]Generating SBOM..."):
        result = generate_design_sbom(
            strictdoc_export_path=strictdoc_export,
            output_path=output,
            source_root=source_root,
            spdx_id_prefix=prefix,
            document_name=name,
            organization=org,
            scan_source_markers=not no_source_scan,
            validate_output=not no_validate,
        )

    # Display result
    if result.success:
        console.print(
            Panel.fit(
                f"[bold green]✓ SBOM generated successfully![/]\n\n"
                f"Output: [cyan]{result.output_path}[/]\n"
                f"Elements: [yellow]{result.element_count}[/]\n"
                f"Relationships: [yellow]{result.relationship_count}[/]\n"
                f"Time: [dim]{result.generation_time:.2f}s[/]",
                border_style="green",
                title="Success",
            )
        )

        # Show warnings if any
        if result.warnings:
            console.print()
            console.print("[yellow]Warnings:[/]")
            for warning in result.warnings:
                console.print(f"  ⚠ {warning}")

        sys.exit(0)
    else:
        console.print(
            Panel.fit(
                f"[bold red]✗ SBOM generation failed![/]",
                border_style="red",
                title="Error",
            )
        )

        for error in result.errors:
            console.print(f"  ✗ {error}", style="red")

        sys.exit(1)


@main.command()
@click.argument(
    "sbom_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--shacl",
    is_flag=True,
    help="Run SHACL validation (requires pyshacl)",
)
@click.pass_context
def validate(ctx: click.Context, sbom_file: Path, shacl: bool) -> None:
    """
    Validate an existing SPDX SBOM file.

    Performs:
    - JSON-LD structure validation
    - SPDX 3.0.1 schema checks
    - xSafety extension validation
    - Optional SHACL shape validation

    Example:

        spdx-xsafety-sbom validate design-sbom.json --shacl

    """
    console.print(
        Panel.fit(
            f"[bold blue]SPDX Validator[/]",
            border_style="blue",
        )
    )

    console.print(f"Validating: [cyan]{sbom_file}[/]")
    console.print()

    try:
        from spdx_xsafety_sbom.validation import validate_sbom

        with console.status("[bold green]Validating SBOM..."):
            result = validate_sbom(sbom_file, run_shacl=shacl)

        if result.valid:
            console.print(
                Panel.fit(
                    "[bold green]✓ SBOM is valid![/]",
                    border_style="green",
                    title="Valid",
                )
            )

            if result.warnings:
                console.print()
                console.print("[yellow]Warnings:[/]")
                for warning in result.warnings:
                    console.print(f"  ⚠ {warning}")

            sys.exit(0)
        else:
            console.print(
                Panel.fit(
                    "[bold red]✗ SBOM validation failed![/]",
                    border_style="red",
                    title="Invalid",
                )
            )

            for error in result.errors:
                console.print(f"  ✗ {error}", style="red")

            sys.exit(1)

    except ImportError as e:
        console.print(f"[red]Validation module not available: {e}[/]")
        console.print("Install with: [cyan]uv add pyshacl rdflib[/]")
        sys.exit(1)


@main.command()
def version() -> None:
    """Display version information."""
    console.print(
        Panel.fit(
            f"[bold]spdx-xsafety-sbom[/] version [cyan]{__version__}[/]\n\n"
            f"SPDX Version: [yellow]3.0.1[/]\n"
            f"xSafety Extension: [yellow]2.1.0[/]\n\n"
            f"[dim]Generate SPDX 3.0.1 Design SBOMs with xSafety extension[/]",
            border_style="blue",
        )
    )


if __name__ == "__main__":
    main()
