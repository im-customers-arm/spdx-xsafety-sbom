# Design SBOM Generation

This document describes the current implementation of `spdx-xsafety-sbom`.

## Overview

`spdx-xsafety-sbom` generates an SPDX 3.0.1 JSON-LD Design SBOM from StrictDoc `.sdoc` requirements and optional `@sdoc[...]` source markers.

Pipeline:

1. Parse StrictDoc requirements into `StrictDocNode` objects
2. Optionally scan source files for `@sdoc[UID]` markers
3. Build SPDX elements with xSafety extensions
4. Build SPDX relationships
5. Assemble JSON-LD document and optionally validate

## Architecture

### Stage 1: StrictDoc Parsing

Module: `src/spdx_xsafety_sbom/strictdoc_parser.py`

Input:
- A directory containing `.sdoc` files
- Or a single `.sdoc` file

Behavior:
- Uses native StrictDoc `SDReader` for standard grammar projects
- Falls back to `strictdoc export --formats json` when custom grammar files (`.sgra`) are detected
- Extracts node metadata including UIDs, safety fields (`ASIL`, `SEVERITY`, `EXPOSURE`, `CONTROLLABILITY`), evidence fields (`ARTIFACT_ID`, `TIMESTAMP_UTC`, `HASH`), and parent relations

Output:
- `dict[str, StrictDocNode]`

### Stage 2: Source Marker Scanning

Module: `src/spdx_xsafety_sbom/source_scanner.py`

Input:
- Optional `source_root`

Behavior:
- Recursively scans configured file extensions in `SCANNABLE_EXTENSIONS`
- Uses regex `@sdoc\[([^\]]+)\]`
- Supports comma-separated UIDs (`@sdoc[SSR-001, SSR-002]`)
- Ignores excluded directories like `.git`, `.venv`, `node_modules`, `build`, and `dist`
- Captures line range and snippet context for each marker

Output:
- `dict[str, list[RangeLink]]`

### Stage 3: SPDX Element Building

Module: `src/spdx_xsafety_sbom/spdx_builder.py`

Node-to-element mapping:

| StrictDoc UID Type | SPDX Element | Extension |
|---|---|---|
| `HAZ-*` | `Bundle` | `xSafety:HazardExtension` |
| `SG-*` | `Bundle` | `xSafety:SafetyGoalExtension` |
| `TSR-*`, `SSR-*`, `HSR-*`, `SWA-*`, `REQ-*` | `Bundle` | `xSafety:SafetyRequirementExtension` |
| `TC-*` | `Bundle` | `xSafety:SafetyTestExtension` |
| `EVID-*` | `software_File` | `xSafety:SafetyEvidenceExtension` |
| Source file marker target | `software_File` | none |

Document-level behavior:
- Generates SPDX IDs as `<prefix><type>-<identifier>`
- Adds `CreationInfo` with tool and optional organization
- Emits JSON-LD `@context` with SPDX and `xSafety`
- Emits `namespaceMap` for `xSafety`

### Stage 4: Relationship Building

Module: `src/spdx_xsafety_sbom/relationships.py`

Generated relationship types:

| Relationship Type | Rule |
|---|---|
| `descendantOf` | Child requirement points to parent requirement |
| `hasTestCase` | Parent requirement points to test case (`TC-*`) |
| `hasEvidence` | Parent requirement/test points to evidence (`EVID-*`) |
| `testedOn` | Requirement points to source `software_File` |

### Stage 5: Output and Validation

Module: `src/spdx_xsafety_sbom/generator.py`

Behavior:
- Writes formatted JSON-LD output to the requested path
- Creates output directories as needed
- Runs built-in structure validation when enabled (`validate_output=True`)

Validation modules:
- `src/spdx_xsafety_sbom/validation/spdx_validator.py`
- `src/spdx_xsafety_sbom/validation/shacl_validator.py`

CLI `validate --shacl` runs SHACL validation when validation extras are installed.

## CLI Usage

```bash
# Generate from StrictDoc directory
uv run spdx-xsafety-sbom generate /path/to/strictdoc -o design-sbom.json

# Generate with explicit source root
uv run spdx-xsafety-sbom generate /path/to/strictdoc -s /path/to/repo -o design-sbom.json

# Validate output
uv run spdx-xsafety-sbom validate design-sbom.json

# Validate with SHACL
uv run spdx-xsafety-sbom validate design-sbom.json --shacl
```

## Programmatic API

```python
from spdx_xsafety_sbom import generate_design_sbom

result = generate_design_sbom(
    strictdoc_export_path="/path/to/strictdoc",
    output_path="design-sbom.json",
    source_root="/path/to/repo",
    document_name="my-design-sbom",
    spdx_id_prefix="urn:spdx:myorg:",
)
```

## Current Limitations

1. Custom grammar projects require StrictDoc CLI export fallback.
2. Source range boundaries are heuristic and derived from local block scanning.
3. Parent/child hierarchy depends on explicit StrictDoc relation fields (`Parent`, `Refines`, `Derives`).
