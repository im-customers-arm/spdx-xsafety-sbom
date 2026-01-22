# StrictDoc Library Integration Plan

**Clean-Slate Refactoring**

This document outlines the implementation plan for refactoring `spdx-xsafety-sbom` to use the StrictDoc library directly, replacing all manual JSON parsing with native Python API access.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Goals](#goals)
3. [Architecture](#architecture)
4. [StrictDoc API Reference](#strictdoc-api-reference)
5. [Implementation Phases](#implementation-phases)
6. [Detailed Code Changes](#detailed-code-changes)
7. [Testing Plan](#testing-plan)
8. [Risks and Mitigations](#risks-and-mitigations)
9. [Success Criteria](#success-criteria)

---

## Executive Summary

### Problem

The current implementation requires users to:
1. Run `strictdoc export --format json` to generate JSON files
2. Run `spdx-xsafety-sbom generate` pointing to the JSON export

This results in:
- **~520 lines of fragile JSON parsing code** handling multiple format variations
- **Duplicated source file scanning** that StrictDoc already performs
- **Duplicated data models** mirroring StrictDoc's internal structures
- **Extra workflow step** for users

### Solution

Replace the entire parsing layer with direct StrictDoc library usage:
- Use `SDReader` to parse `.sdoc` files directly
- Use `TraceabilityIndex` for relationships and source file links
- Delete `strictdoc_parser.py` and `source_scanner.py` entirely

### Impact

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Lines of parsing code | ~520 | ~150 | -70% |
| User workflow steps | 2 | 1 | -50% |
| Input format | JSON export | Native `.sdoc` | Simplified |
| Source scanning | Manual regex | StrictDoc built-in | Eliminated |

---

## Goals

1. **Replace** `strictdoc_parser.py` with `strictdoc_adapter.py`
2. **Delete** `source_scanner.py` entirely
3. **Simplify** `StrictDocNode` model or eliminate it
4. **Update** CLI to accept `.sdoc` project path directly
5. **Update** all tests to use `.sdoc` fixtures

---

## Architecture

### Before

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  .sdoc files    │────▶│  strictdoc CLI   │────▶│  JSON export    │
└─────────────────┘     │  (external)      │     │  (files)        │
                        └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  SPDX JSON-LD   │◀────│  spdx_builder.py │◀────│ strictdoc_      │
│  output         │     │  relationships.py│     │ parser.py       │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          ▲
┌─────────────────┐     ┌──────────────────┐              │
│  Source files   │────▶│ source_scanner.py│──────────────┘
│  (@sdoc markers)│     └──────────────────┘
└─────────────────┘
```

### After

```
┌─────────────────┐
│  .sdoc files    │──────────────────┐
└─────────────────┘                  │
                                     ▼
┌─────────────────┐     ┌────────────────────┐     ┌─────────────────┐
│  Source files   │────▶│  strictdoc library │────▶│  DocumentTree   │
│  (@sdoc markers)│     │  (imported)        │     │  + Traceability │
└─────────────────┘     └────────────────────┘     └────────┬────────┘
                                                            │
                                                            ▼
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  SPDX JSON-LD   │◀────│  spdx_builder.py │◀────│ strictdoc_adapter │
│  output         │     │  relationships.py│     │ (~150 lines)      │
└─────────────────┘     └──────────────────┘     └───────────────────┘
```

---

## StrictDoc API Reference

### Key Imports

```python
# Document parsing
from strictdoc.backend.sdoc.reader import SDReader

# Data models
from strictdoc.backend.sdoc.models.document import SDocDocument
from strictdoc.backend.sdoc.models.requirement import SDocRequirement

# Project structure
from strictdoc.core.project_config import ProjectConfigLoader
from strictdoc.core.document_tree import DocumentTree

# Traceability (parent-child + source file links)
from strictdoc.core.traceability_index import TraceabilityIndex
from strictdoc.core.traceability_index_builder import TraceabilityIndexBuilder
```

### Key Data Structures

#### SDocRequirement

```python
class SDocRequirement:
    reserved_uid: Optional[str]          # UID field
    reserved_title: Optional[str]        # TITLE field
    reserved_statement: Optional[str]    # STATEMENT field
    reserved_rationale: Optional[str]    # RATIONALE field
    reserved_comments: List[str]         # COMMENT fields
    relations: List[Reference]           # RELATIONS (parent links, etc.)
    ordered_fields_lookup: Dict[str, List[SDocNodeField]]  # Custom fields
```

#### TraceabilityIndex

```python
class TraceabilityIndex:
    def get_parent_requirements(self, node) -> List[SDocRequirement]
    def get_children_requirements(self, node) -> List[SDocRequirement]
    def get_node_by_uid(self, uid: str) -> Optional[SDocNode]
    def get_requirement_file_links(self, uid: str) -> List[FileReference]
```

#### FileReference (Source Traceability)

```python
class FileReference:
    g_file_path: str        # Relative file path
    g_file_line_begin: int  # Start line (1-indexed)
    g_file_line_end: int    # End line (1-indexed)
```

---

## Implementation Phases

### Phase 1: Add Dependency & Create Adapter

**Duration:** 1-2 days

#### Tasks

- [ ] Add `strictdoc>=0.32.0,<0.34.0` to `pyproject.toml`
- [ ] Run `uv lock` to update lock file
- [ ] Create `src/spdx_xsafety_sbom/strictdoc_adapter.py`
- [ ] Implement `StrictDocAdapter` class

#### Files

| File | Action |
|------|--------|
| `pyproject.toml` | Add strictdoc dependency |
| `uv.lock` | Regenerate |
| `strictdoc_adapter.py` | Create new |

---

### Phase 2: Update Generator & CLI

**Duration:** 1 day

#### Tasks

- [ ] Update `generator.py` to use `StrictDocAdapter`
- [ ] Update `cli.py` to accept project path (not JSON export path)
- [ ] Remove source scanning parameter (now automatic)
- [ ] Update help text and examples

#### Files

| File | Action |
|------|--------|
| `generator.py` | Modify to use adapter |
| `cli.py` | Simplify arguments |

---

### Phase 3: Update Tests & Fixtures

**Duration:** 1 day

#### Tasks

- [ ] Create `.sdoc` test fixtures (replace JSON fixtures)
- [ ] Update `conftest.py` with new fixture paths
- [ ] Rewrite `test_strictdoc_parser.py` → `test_strictdoc_adapter.py`
- [ ] Update integration tests
- [ ] Delete JSON test fixtures

#### Files

| File | Action |
|------|--------|
| `tests/fixtures/strictdoc-export/` | Delete directory |
| `tests/fixtures/sdoc-project/` | Create new |
| `tests/test_strictdoc_parser.py` | Delete |
| `tests/test_strictdoc_adapter.py` | Create new |
| `tests/conftest.py` | Update fixtures |

---

### Phase 4: Delete Old Code & Cleanup

**Duration:** 0.5 days

#### Tasks

- [ ] Delete `strictdoc_parser.py`
- [ ] Delete `source_scanner.py`
- [ ] Delete `test_source_scanner.py`
- [ ] Remove unused constants from `constants.py`
- [ ] Update README.md with new usage
- [ ] Update CONTRIBUTING.md if needed

#### Files

| File | Action |
|------|--------|
| `strictdoc_parser.py` | Delete |
| `source_scanner.py` | Delete |
| `test_source_scanner.py` | Delete |
| `constants.py` | Remove `SDOC_MARKER_PATTERN`, `SCANNABLE_EXTENSIONS` |
| `README.md` | Update usage examples |

---

### Phase 5: Final Validation

**Duration:** 0.5 days

#### Tasks

- [ ] Run full test suite
- [ ] Run linter (`uv run ruff check`)
- [ ] Run type checker (`uv run mypy`)
- [ ] Test with real StrictDoc project
- [ ] Verify generated SBOM validates

---

## Detailed Code Changes

### `pyproject.toml`

```toml
[project]
name = "spdx-xsafety-sbom"
version = "0.2.0"
description = "Generate SPDX 3.0.1 Design SBOMs with xSafety extension from StrictDoc projects"
# ...

dependencies = [
    "click>=8.1.0",
    "rich>=13.0.0",
    "pydantic>=2.0.0",
    "strictdoc>=0.32.0,<0.34.0",
]
```

---

### `src/spdx_xsafety_sbom/strictdoc_adapter.py` (New File)

```python
"""
StrictDoc library adapter.

Provides direct access to StrictDoc's Python API for parsing .sdoc files
and extracting requirements with full traceability information.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from spdx_xsafety_sbom.models import RangeLink, StrictDocNode

if TYPE_CHECKING:
    from strictdoc.backend.sdoc.models.requirement import SDocRequirement
    from strictdoc.core.document_tree import DocumentTree
    from strictdoc.core.traceability_index import TraceabilityIndex

logger = logging.getLogger(__name__)


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
        self.project_path = Path(project_path)
        self._document_tree: DocumentTree | None = None
        self._traceability_index: TraceabilityIndex | None = None
        self._nodes: dict[str, StrictDocNode] = {}

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
        from strictdoc.core.document_tree import DocumentTree
        from strictdoc.core.traceability_index_builder import TraceabilityIndexBuilder
        from strictdoc.backend.sdoc.reader import SDReader

        # Load project config (or use defaults)
        config = ProjectConfigLoader.load_from_path_or_get_default(
            self.project_path,
            environment=None,
        )

        # Build document tree from .sdoc files
        reader = SDReader()
        self._document_tree = DocumentTree.create_from_config(config, reader)

        # Build traceability index
        self._traceability_index = TraceabilityIndexBuilder.create(
            document_tree=self._document_tree,
            project_config=config,
        )

    def _extract_nodes(self) -> None:
        """Extract all requirement nodes from document tree."""
        for document in self._document_tree.document_list:
            for node in self._iterate_requirements(document):
                if not node.reserved_uid:
                    continue

                sdoc_node = self._convert_node(node)
                self._nodes[sdoc_node.uid] = sdoc_node

    def _iterate_requirements(self, document) -> Iterator[SDocRequirement]:
        """Recursively iterate all requirement nodes in a document."""
        from strictdoc.backend.sdoc.models.requirement import SDocRequirement

        def walk(node):
            if isinstance(node, SDocRequirement):
                yield node
            if hasattr(node, "section_contents"):
                for child in node.section_contents:
                    yield from walk(child)

        for content in document.section_contents:
            yield from walk(content)

    def _convert_node(self, node: SDocRequirement) -> StrictDocNode:
        """Convert SDocRequirement to StrictDocNode."""
        return StrictDocNode(
            uid=node.reserved_uid,
            title=node.reserved_title,
            statement=self._extract_statement(node),
            rationale=node.reserved_rationale,
            comment=node.reserved_comments[0] if node.reserved_comments else None,
            node_type=getattr(node, "requirement_type", "REQUIREMENT") or "REQUIREMENT",
            asil=self._get_field(node, "ASIL"),
            severity=self._get_field(node, "SEVERITY"),
            exposure=self._get_field(node, "EXPOSURE"),
            controllability=self._get_field(node, "CONTROLLABILITY"),
            parent_uids=self._extract_parent_uids(node),
            document_path=self._get_document_path(node),
        )

    def _extract_statement(self, node: SDocRequirement) -> str | None:
        """Extract statement text from node."""
        stmt = node.reserved_statement
        if stmt is None:
            return None
        if hasattr(stmt, "statement_text"):
            return stmt.statement_text
        return str(stmt)

    def _get_field(self, node: SDocRequirement, name: str) -> str | None:
        """Get custom field value."""
        if not hasattr(node, "ordered_fields_lookup"):
            return None
        fields = node.ordered_fields_lookup.get(name, [])
        return fields[0].field_value if fields else None

    def _extract_parent_uids(self, node: SDocRequirement) -> list[str]:
        """Extract parent UIDs from relations."""
        parents = []
        for relation in getattr(node, "relations", []) or []:
            ref_uid = getattr(relation, "ref_uid", None)
            ref_type = getattr(relation, "ref_type", "Parent")
            if ref_uid and str(ref_type).lower() in ("parent", "refines", "derives"):
                parents.append(ref_uid)
        return parents

    def _get_document_path(self, node: SDocRequirement) -> Path | None:
        """Get source document path."""
        if node.document and hasattr(node.document, "meta"):
            return Path(node.document.meta.input_doc_full_path)
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
        """
        if self._traceability_index is None:
            raise RuntimeError("Must call parse() first")

        links: dict[str, list[RangeLink]] = {}

        for uid in self._nodes:
            file_refs = self._traceability_index.get_requirement_file_links(uid)
            if not file_refs:
                continue

            links[uid] = [
                RangeLink(
                    file_path=Path(ref.g_file_path),
                    line_start=ref.g_file_line_begin,
                    line_end=ref.g_file_line_end,
                    uid=uid,
                    snippet=None,
                )
                for ref in file_refs
            ]

        total = sum(len(v) for v in links.values())
        logger.info("Found %d source links across %d UIDs", total, len(links))
        return links

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
```

---

### `src/spdx_xsafety_sbom/generator.py` (Updated)

```python
"""
Main generator orchestration module.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom.models import GenerationResult
from spdx_xsafety_sbom.relationships import RelationshipBuilder
from spdx_xsafety_sbom.spdx_builder import SPDX3Builder
from spdx_xsafety_sbom.strictdoc_adapter import StrictDocAdapter

if TYPE_CHECKING:
    from spdx_xsafety_sbom.models import RangeLink, StrictDocNode

logger = logging.getLogger(__name__)


def generate_design_sbom(
    project_path: Path | str,
    output_path: Path | str,
    spdx_id_prefix: str = "urn:spdx:example:",
    document_name: str = "design-sbom",
    tool_name: str = "spdx-xsafety-sbom",
    organization: str | None = None,
    validate_output: bool = True,
) -> GenerationResult:
    """
    Generate an SPDX 3.0.1 Design SBOM with xSafety extensions.

    Args:
        project_path: Path to StrictDoc project (containing .sdoc files).
        output_path: Path for output SBOM file.
        spdx_id_prefix: Prefix for SPDX element IDs.
        document_name: Name for the SPDX document.
        tool_name: Name of the generating tool.
        organization: Optional organization name.
        validate_output: Whether to validate generated SBOM.

    Returns:
        GenerationResult with success status and details.
    """
    start_time = time.time()
    result = GenerationResult(success=False)

    try:
        proj_path = Path(project_path)
        out_path = Path(output_path)

        logger.info("Starting SBOM generation")
        logger.info("  Project path: %s", proj_path)
        logger.info("  Output: %s", out_path)

        # =================================================================
        # Step 1: Parse StrictDoc project
        # =================================================================
        logger.info("Parsing StrictDoc project...")
        adapter = StrictDocAdapter(proj_path)
        nodes = adapter.parse()

        if not nodes:
            result.errors.append("No requirements found in StrictDoc project")
            return result

        logger.info("Found %d requirements", len(nodes))

        # =================================================================
        # Step 2: Get source file links (from StrictDoc traceability)
        # =================================================================
        logger.info("Extracting source file traceability...")
        source_links = adapter.get_source_links()
        logger.info("Found source links for %d UIDs", len(source_links))

        # =================================================================
        # Step 3: Build SPDX elements
        # =================================================================
        logger.info("Building SPDX elements...")
        builder = SPDX3Builder(
            spdx_id_prefix=spdx_id_prefix,
            document_name=document_name,
        )

        builder.build_creation_info(
            tool_name=tool_name,
            tool_version="0.2.0",
            organization=organization,
        )

        root_elements: list[str] = []
        for uid, node in nodes.items():
            element = builder.build_node_element(node)
            if not node.parent_uids:
                root_elements.append(element["spdxId"])

        logger.info("Built %d elements", len(builder.elements))

        # =================================================================
        # Step 4: Build relationships
        # =================================================================
        logger.info("Building relationships...")
        rel_builder = RelationshipBuilder(builder)
        relationships = rel_builder.build_all_relationships(
            nodes=nodes,
            source_links=source_links if source_links else None,
            source_root=str(proj_path),
        )

        for rel in relationships:
            builder._add_element(rel)

        logger.info("Built %d relationships", len(relationships))

        # =================================================================
        # Step 5: Build document and write output
        # =================================================================
        logger.info("Building SPDX document...")
        document = builder.build_document(root_elements=root_elements)

        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, ensure_ascii=False)

        logger.info("Wrote SBOM to %s", out_path)

        # =================================================================
        # Step 6: Validate output
        # =================================================================
        if validate_output:
            validation_warnings = _validate_document(document)
            result.warnings.extend(validation_warnings)

        # =================================================================
        # Build result
        # =================================================================
        result.success = True
        result.output_path = out_path
        result.document = document
        result.element_count = len(builder.elements)
        result.relationship_count = len(relationships)
        result.generation_time = time.time() - start_time

        logger.info(
            "Generation complete: %d elements, %d relationships in %.2fs",
            result.element_count,
            result.relationship_count,
            result.generation_time,
        )

    except FileNotFoundError as e:
        result.errors.append(f"File not found: {e}")
        logger.error("Generation failed: %s", e)

    except Exception as e:
        result.errors.append(f"Generation failed: {e}")
        logger.exception("Generation failed with exception")

    return result


def _validate_document(document: dict[str, Any]) -> list[str]:
    """Basic validation of generated SPDX document."""
    warnings: list[str] = []

    if "@context" not in document:
        warnings.append("Missing @context in document")

    if "@graph" not in document:
        warnings.append("Missing @graph in document")
        return warnings

    graph = document["@graph"]
    if not graph:
        warnings.append("Empty @graph in document")
        return warnings

    spdx_docs = [e for e in graph if e.get("@type") == "SpdxDocument"]
    if not spdx_docs:
        warnings.append("No SpdxDocument element found")
    elif len(spdx_docs) > 1:
        warnings.append("Multiple SpdxDocument elements found")

    return warnings
```

---

### `src/spdx_xsafety_sbom/cli.py` (Updated)

```python
"""
CLI for SPDX xSafety SBOM generator.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from spdx_xsafety_sbom import __version__
from spdx_xsafety_sbom.generator import generate_design_sbom

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
    from StrictDoc projects.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@main.command()
@click.argument(
    "project_path",
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
    "--no-validate",
    is_flag=True,
    help="Disable output validation",
)
@click.pass_context
def generate(
    ctx: click.Context,
    project_path: Path,
    output: Path,
    prefix: str,
    name: str,
    org: str | None,
    no_validate: bool,
) -> None:
    """
    Generate an SPDX 3.0.1 Design SBOM from a StrictDoc project.

    PROJECT_PATH is the root directory containing .sdoc files.

    Example:

        spdx-xsafety-sbom generate ./my-project -o design-sbom.json

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
    config_table.add_row("Project Path", str(project_path))
    config_table.add_row("Output", str(output))
    config_table.add_row("SPDX ID Prefix", prefix)
    config_table.add_row("Document Name", name)
    config_table.add_row("Organization", org or "None")
    config_table.add_row("Validation", "Disabled" if no_validate else "Enabled")
    console.print(config_table)
    console.print()

    # Generate SBOM
    with console.status("[bold green]Generating SBOM..."):
        result = generate_design_sbom(
            project_path=project_path,
            output_path=output,
            spdx_id_prefix=prefix,
            document_name=name,
            organization=org,
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

        if result.warnings:
            console.print()
            console.print("[yellow]Warnings:[/]")
            for warning in result.warnings:
                console.print(f"  ⚠ {warning}")

        sys.exit(0)
    else:
        console.print(
            Panel.fit(
                "[bold red]✗ SBOM generation failed![/]",
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

    Example:

        spdx-xsafety-sbom validate design-sbom.json --shacl

    """
    console.print(
        Panel.fit(
            "[bold blue]SPDX Validator[/]",
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
```

---

### Test Fixture: `tests/fixtures/sdoc-project/requirements.sdoc`

```sdoc
[DOCUMENT]
TITLE: Sample Safety Requirements

[GRAMMAR]
ELEMENTS:
- TAG: REQUIREMENT
  FIELDS:
  - TITLE: UID
    TYPE: String
    REQUIRED: True
  - TITLE: TITLE
    TYPE: String
    REQUIRED: False
  - TITLE: STATEMENT
    TYPE: String
    REQUIRED: False
  - TITLE: ASIL
    TYPE: String
    REQUIRED: False
  - TITLE: SEVERITY
    TYPE: String
    REQUIRED: False
  - TITLE: EXPOSURE
    TYPE: String
    REQUIRED: False
  - TITLE: CONTROLLABILITY
    TYPE: String
    REQUIRED: False
  - TITLE: RATIONALE
    TYPE: String
    REQUIRED: False
  RELATIONS:
  - TYPE: Parent

[REQUIREMENT]
UID: HAZ-001
TITLE: Missing CAM message not detected
STATEMENT: Missing CAM message not detected within timeout period
ASIL: ASIL_B
SEVERITY: S2
EXPOSURE: E3
CONTROLLABILITY: C2

[REQUIREMENT]
UID: SG-001
TITLE: CAM message timeout detection
STATEMENT: Ensure CAM message reception is monitored with timeout detection
ASIL: ASIL_B
RELATIONS:
- TYPE: Parent
  VALUE: HAZ-001

[REQUIREMENT]
UID: SSR-001
TITLE: Timer scheduling
STATEMENT: cam-service shall schedule a per-event timer that triggers a safety violation if the next event is not received within 1000ms
ASIL: ASIL_B
RELATIONS:
- TYPE: Parent
  VALUE: SG-001

[REQUIREMENT]
UID: SSR-002
TITLE: Timer cancellation
STATEMENT: cam-service shall cancel the timer when a valid event is received
ASIL: ASIL_B
RELATIONS:
- TYPE: Parent
  VALUE: SG-001

[REQUIREMENT]
UID: TC-001
TITLE: Test timer trigger
STATEMENT: Verify timer triggers on missing CAM message
ASIL: ASIL_B
RELATIONS:
- TYPE: Parent
  VALUE: SSR-001
```

---

### `tests/test_strictdoc_adapter.py` (New File)

```python
"""Tests for StrictDoc adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from spdx_xsafety_sbom.strictdoc_adapter import StrictDocAdapter, parse_strictdoc_project


class TestStrictDocAdapter:
    """Tests for StrictDocAdapter class."""

    def test_parse_project(self, sdoc_project_dir: Path) -> None:
        """Test parsing a StrictDoc project."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        nodes = adapter.parse()

        assert len(nodes) >= 5
        assert "HAZ-001" in nodes
        assert "SG-001" in nodes
        assert "SSR-001" in nodes
        assert "SSR-002" in nodes
        assert "TC-001" in nodes

    def test_hazard_fields(self, sdoc_project_dir: Path) -> None:
        """Test HARA fields are extracted correctly."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        nodes = adapter.parse()

        haz = nodes["HAZ-001"]
        assert haz.uid == "HAZ-001"
        assert haz.asil == "ASIL_B"
        assert haz.severity == "S2"
        assert haz.exposure == "E3"
        assert haz.controllability == "C2"
        assert haz.get_requirement_type() == "HAZ"

    def test_parent_relationships(self, sdoc_project_dir: Path) -> None:
        """Test parent UIDs are extracted."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        nodes = adapter.parse()

        sg = nodes["SG-001"]
        assert "HAZ-001" in sg.parent_uids

        ssr = nodes["SSR-001"]
        assert "SG-001" in ssr.parent_uids

    def test_child_relationships(self, sdoc_project_dir: Path) -> None:
        """Test child UIDs are computed."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        nodes = adapter.parse()

        haz = nodes["HAZ-001"]
        assert "SG-001" in haz.child_uids

        sg = nodes["SG-001"]
        assert "SSR-001" in sg.child_uids
        assert "SSR-002" in sg.child_uids

    def test_get_hazards(self, sdoc_project_dir: Path) -> None:
        """Test get_hazards convenience method."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        adapter.parse()

        hazards = adapter.get_hazards()
        assert len(hazards) == 1
        assert hazards[0].uid == "HAZ-001"

    def test_get_safety_goals(self, sdoc_project_dir: Path) -> None:
        """Test get_safety_goals convenience method."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        adapter.parse()

        goals = adapter.get_safety_goals()
        assert len(goals) == 1
        assert goals[0].uid == "SG-001"

    def test_get_requirements(self, sdoc_project_dir: Path) -> None:
        """Test get_requirements convenience method."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        adapter.parse()

        reqs = adapter.get_requirements()
        uids = {r.uid for r in reqs}
        assert "SSR-001" in uids
        assert "SSR-002" in uids

    def test_get_test_cases(self, sdoc_project_dir: Path) -> None:
        """Test get_test_cases convenience method."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        adapter.parse()

        tests = adapter.get_test_cases()
        assert len(tests) == 1
        assert tests[0].uid == "TC-001"

    def test_missing_project_raises(self, tmp_path: Path) -> None:
        """Test FileNotFoundError for missing project."""
        adapter = StrictDocAdapter(tmp_path / "nonexistent")

        with pytest.raises(FileNotFoundError):
            adapter.parse()

    def test_convenience_function(self, sdoc_project_dir: Path) -> None:
        """Test parse_strictdoc_project function."""
        nodes = parse_strictdoc_project(sdoc_project_dir)

        assert len(nodes) >= 5
        assert "HAZ-001" in nodes


class TestSourceLinks:
    """Tests for source file traceability."""

    def test_get_source_links_empty(self, sdoc_project_dir: Path) -> None:
        """Test source links when no source files present."""
        adapter = StrictDocAdapter(sdoc_project_dir)
        adapter.parse()

        links = adapter.get_source_links()
        # May be empty if no source files with @sdoc markers
        assert isinstance(links, dict)

    def test_source_links_requires_parse(self, sdoc_project_dir: Path) -> None:
        """Test that get_source_links requires parse() first."""
        adapter = StrictDocAdapter(sdoc_project_dir)

        with pytest.raises(RuntimeError):
            adapter.get_source_links()
```

---

### `tests/conftest.py` (Updated)

```python
"""Pytest configuration and fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sdoc_project_dir(fixtures_dir: Path) -> Path:
    """Return path to sample StrictDoc project."""
    return fixtures_dir / "sdoc-project"


@pytest.fixture
def sample_source_dir(fixtures_dir: Path) -> Path:
    """Return path to sample source files."""
    return fixtures_dir / "source"
```

---

## Files to Delete

| File | Reason |
|------|--------|
| `src/spdx_xsafety_sbom/strictdoc_parser.py` | Replaced by `strictdoc_adapter.py` |
| `src/spdx_xsafety_sbom/source_scanner.py` | StrictDoc handles source traceability |
| `tests/test_strictdoc_parser.py` | Replaced by `test_strictdoc_adapter.py` |
| `tests/test_source_scanner.py` | No longer needed |
| `tests/fixtures/strictdoc-export/` | Replaced by `sdoc-project/` |

---

## Constants to Remove from `constants.py`

```python
# DELETE these (source scanning no longer needed):
SDOC_MARKER_PATTERN
SDOC_MULTILINE_PATTERN
SCANNABLE_EXTENSIONS
```

---

## Testing Plan

### Commands

```bash
# Install with new dependency
uv sync --dev

# Run all tests
uv run pytest -v

# Run adapter tests only
uv run pytest tests/test_strictdoc_adapter.py -v

# Run with coverage
uv run pytest --cov=spdx_xsafety_sbom --cov-report=term-missing

# Type checking
uv run mypy src/spdx_xsafety_sbom/

# Linting
uv run ruff check src/
uv run ruff format src/
```

### Manual Testing

```bash
# Generate SBOM from test fixture
uv run spdx-xsafety-sbom generate tests/fixtures/sdoc-project -o test-output.json

# Validate output
uv run spdx-xsafety-sbom validate test-output.json
```

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| StrictDoc API changes | Medium | High | Pin version `>=0.32.0,<0.34.0` |
| Import time increases | Low | Low | Acceptable trade-off |
| Missing custom field | Medium | Medium | Test all field types |
| TraceabilityIndex API differs | Low | Medium | Verify with StrictDoc source |

---

## Success Criteria

### Done When:

- [ ] `strictdoc_adapter.py` created and tested
- [ ] `generator.py` uses adapter exclusively
- [ ] `cli.py` accepts project path directly
- [ ] All old parsing code deleted
- [ ] Test suite passes with new fixtures
- [ ] README updated with new usage
- [ ] `uv run ruff check` passes
- [ ] `uv run mypy` passes
- [ ] Manual test with real StrictDoc project succeeds

---

## Summary

| Metric | Value |
|--------|-------|
| Files to create | 2 |
| Files to modify | 5 |
| Files to delete | 5 |
| Net lines removed | ~400 |
| New dependency | `strictdoc>=0.32.0` |

