# Design SBOM Generation

This document describes how the `spdx-xsafety-sbom` tool generates SPDX 3.0.1 Design SBOMs with xSafety extensions from StrictDoc safety requirements.

## Overview

The tool transforms StrictDoc safety artifacts (hazards, safety goals, requirements, tests, evidence) into an SPDX 3.0.1 JSON-LD Software Bill of Materials with functional safety metadata via the xSafety extension profile.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  StrictDoc      │     │  spdx-xsafety    │     │  SPDX 3.0.1     │
│  .sdoc files    │ ──► │  -sbom           │ ──► │  Design SBOM    │
│  + source code  │     │                  │     │  + xSafety ext  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Architecture

### Hybrid Parsing Mode

The tool uses a **hybrid parsing strategy** to support both default and custom StrictDoc grammars:

```
                    ┌─────────────────────────────────┐
                    │  .sdoc files + optional .sgra   │
                    └────────────────┬────────────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │  Custom grammar       │
                         │  detected?            │
                         │  (.sgra or            │
                         │   strictdoc.toml)     │
                         └───────────┬───────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
        ┌───────────────────┐             ┌───────────────────┐
        │  Yes: Custom      │             │  No: Default      │
        │                   │             │                   │
        │  strictdoc export │             │  Native SDReader  │
        │  --formats json   │             │  .read()          │
        │  → parse JSON     │             │                   │
        └─────────┬─────────┘             └─────────┬─────────┘
                  │                                 │
                  └────────────────┬────────────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │  StrictDocNode        │
                       │  objects              │
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │  SourceScanner        │
                       │  @sdoc[UID] markers   │
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │  SPDX3Builder         │
                       │  + xSafety extensions │
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │  JSON-LD Design SBOM  │
                       │  (SPDX 3.0.1)         │
                       └───────────────────────┘
```

### Why Hybrid?

StrictDoc's public `SDReader` API only supports the **default grammar**. Custom node types (e.g., `HAZARD`, `TSR`, `SSR`, `SWA`, `TEST_CASE`, `EVIDENCE`) defined in `.sgra` files require the full StrictDoc export pipeline, which internally builds a dynamic grammar model.

| Grammar Type | Parsing Method | Notes |
|--------------|----------------|-------|
| Default | `SDReader.read()` | Direct, fast, native |
| Custom (.sgra) | `strictdoc export --formats json` | Uses StrictDoc CLI, parses resulting JSON |

## Processing Stages

### Stage 1: StrictDoc Parsing

**Module**: `src/spdx_xsafety_sbom/strictdoc_parser.py`

Parses StrictDoc artifacts and extracts:
- Requirements with UIDs (HAZ-001, SG-001, TSR-001, SSR-001, etc.)
- Safety metadata (ASIL levels, HARA ratings)
- Traceability links (parent/child relationships)
- Document structure

**Detection logic**:
```python
has_custom_grammar = (
    (path / "strictdoc.toml").exists()
    or list(path.glob("*.sgra"))
)
```

**Output**: `dict[str, StrictDocNode]` mapping UID to node data

### Stage 2: Source Code Scanning

**Module**: `src/spdx_xsafety_sbom/source_scanner.py`

Scans source files for `@sdoc[UID]` markers that link code to requirements:

```c
// @sdoc[SSR-008]
void handle_timeout(void) {
    // Implementation
}
```

**Scanning modes**:
| File Type | Method | Parser |
|-----------|--------|--------|
| C/C++ (.c, .cpp, .h) | Native | StrictDoc tree-sitter reader |
| Python (.py) | Native | StrictDoc tree-sitter reader |
| Other | Fallback | Regex pattern matching |

**Output**: `dict[str, list[RangeLink]]` mapping UID to source locations

### Stage 3: SPDX Element Building

**Module**: `src/spdx_xsafety_sbom/spdx_builder.py`

Converts parsed nodes to SPDX 3.0.1 elements:

| StrictDoc Node | SPDX Element | xSafety Extension |
|----------------|--------------|-------------------|
| HAZ-* (Hazard) | Bundle | `xSafety:HazardExtension` |
| SG-* (Safety Goal) | Bundle | `xSafety:SafetyGoalExtension` |
| TSR-* (Technical Safety Req) | Bundle | `xSafety:SafetyRequirementExtension` |
| SSR-* (Software Safety Req) | Bundle | `xSafety:SafetyRequirementExtension` |
| SWA-* (Software Architecture) | Bundle | `xSafety:SafetyRequirementExtension` |
| TC-* (Test Case) | Bundle | `xSafety:SafetyTestExtension` |
| EVID-* (Evidence) | Bundle | `xSafety:SafetyEvidenceExtension` |
| Source location | software_File | PositionalRange snippet |

### Stage 4: Relationship Building

**Module**: `src/spdx_xsafety_sbom/relationships.py`

Creates SPDX Relationships from traceability links:

| Relationship Type | Usage |
|-------------------|-------|
| `SPECIFICATION` | Requirement hierarchy (parent → child) |
| `hasTestCase` | Requirement → Test Case |
| `hasEvidence` | Requirement → Evidence |
| `testedOn` | Test → Source file with PositionalRange |

### Stage 5: Document Assembly & Output

**Module**: `src/spdx_xsafety_sbom/generator.py`

Orchestrates the full pipeline:
1. Parse StrictDoc artifacts
2. Scan source code for markers
3. Build SPDX elements with xSafety extensions
4. Build relationships
5. Assemble SpdxDocument with namespaceMap
6. Write JSON-LD output
7. Optionally validate output

## xSafety Extension Profile

The tool implements the xSafety extension profile (v2.1.0) defined in `spdx_extensions/specs/safety-profile.md`.

### Namespace

```json
{
  "@context": [
    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    { "xSafety": "https://example.org/spdx-extensions/xSafety/" }
  ]
}
```

### Extension Classes

| Class | Properties |
|-------|------------|
| `HazardExtension` | severity, exposure, controllability, safetyIntegrityLevel |
| `SafetyGoalExtension` | safetyIntegrityLevel |
| `SafetyRequirementExtension` | requirementType, safetyIntegrityLevel |
| `SafetyTestExtension` | testType, testResult |
| `SafetyEvidenceExtension` | evidenceType, evidenceResult |

### Example Output

```json
{
  "@type": "Bundle",
  "spdxId": "urn:spdx:example:element-HAZ-001",
  "name": "HAZ-001",
  "description": "Missing CAM message not detected...",
  "primaryPurpose": "requirement",
  "extension": [{
    "type": "xSafety:HazardExtension",
    "xSafety:severity": "s2",
    "xSafety:exposure": "e3",
    "xSafety:controllability": "c2",
    "xSafety:safetyIntegrityLevel": "asilB"
  }]
}
```

## Usage

### Basic Usage

```bash
# Generate SBOM from StrictDoc export directory
spdx-xsafety-sbom generate /path/to/strictdoc -o design-sbom.json

# With source code scanning
spdx-xsafety-sbom generate /path/to/strictdoc -s /path/to/source -o design-sbom.json
```

### With Custom Grammar (e.g., CAM project)

```bash
# The tool auto-detects custom grammar files (.sgra, strictdoc.toml)
spdx-xsafety-sbom generate /path/to/cam/docs/strictdoc \
  -s /path/to/cam \
  -o cam-design-sbom.json
```

### Programmatic Usage

```python
from spdx_xsafety_sbom import generate_design_sbom

generate_design_sbom(
    strictdoc_export_path="/path/to/strictdoc",
    output_path="design-sbom.json",
    source_root="/path/to/source",
    document_name="my-project-sbom",
    spdx_id_prefix="urn:spdx:myorg:",
)
```

## Configuration

### UID Prefix Mapping

The tool maps UID prefixes to xSafety extension types via `constants.py`:

```python
REQUIREMENT_TYPES = {
    "TSR": "technicalSafetyRequirement",
    "SSR": "softwareSafetyRequirement",
    "HSR": "hardwareSafetyRequirement",
    "SWA": "functional",
    "HAZ": "hazard",
    "SG": "safetyGoal",
}
```

### Supported Safety Standards

The xSafety extension supports vocabulary from:
- **ISO 26262** - Automotive (ASIL A-D, S0-S3, E0-E4, C0-C3)
- **IEC 61508** - Industrial (SIL 1-4)
- **DO-178C** - Aerospace (DAL A-E)
- **IEC 62304** - Medical devices

## Validation

The tool includes validation for:
- SPDX 3.0.1 structure compliance
- xSafety extension namespace and class validity
- Required properties per extension type
- Optional SHACL-based RDF validation

```bash
# Validate existing SBOM
spdx-xsafety-sbom validate design-sbom.json
```

## Limitations

1. **Custom Grammar API**: StrictDoc's `SDReader` doesn't expose custom grammar loading, requiring the CLI export workaround
2. **Source Scanning**: Native tree-sitter support limited to C/C++ and Python; other languages use regex fallback
3. **Relationship Inference**: Parent/child relationships must be explicit in StrictDoc `RELATIONS` fields

## File Structure

```
src/spdx_xsafety_sbom/
├── __init__.py           # Package exports
├── cli.py                # Command-line interface
├── constants.py          # SPDX/xSafety vocabularies
├── generator.py          # Main orchestration
├── models.py             # Data classes (StrictDocNode, RangeLink)
├── paths.py              # Path utilities (frozen/dev, SHACL shapes)
├── relationships.py      # SPDX relationship builder
├── source_scanner.py     # @sdoc marker scanner
├── spdx_builder.py       # SPDX element builder
├── strictdoc_parser.py   # StrictDoc artifact parser
└── validation/
    ├── shacl_validator.py  # RDF/SHACL validation
    └── spdx_validator.py   # Structure validation
```
