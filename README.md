# spdx-xsafety-sbom

Generate **SPDX 3.0.1 compliant Design SBOMs** with the **xSafety extension** from StrictDoc artifacts.

## Overview

This tool generates Design SBOMs (Software Bill of Materials) for safety-critical systems, following:

- **SPDX 3.0.1** Core and Software profiles
- **xSafety Extension v2.1.0** for functional safety metadata (ISO 26262, DO-178C, IEC 61508)

### What is a Design SBOM?

Unlike traditional SBOMs that document software packages and dependencies, a **Design SBOM** documents:

- Hazard Analysis (HARA)
- Safety Goals
- Technical Safety Requirements (TSR)
- Software Safety Requirements (SSR)
- Architecture elements (SWA)
- Test Cases
- Evidence artifacts

### xSafety Extension Classes

| Class | Description |
|-------|-------------|
| `HazardExtension` | ISO 26262 HARA: severity, exposure, controllability, ASIL |
| `SafetyGoalExtension` | Safety goals with ASIL classification |
| `SafetyRequirementExtension` | TSR/SSR with requirement type |
| `SafetyExtension` | General safety classification |
| `SafetyTestExtension` | Test documentation |
| `SafetyEvidenceExtension` | Evidence artifacts |

## Installation

### Prerequisites

- **Python 3.12+**
- **UV** package manager ([installation guide](https://github.com/astral-sh/uv))

### Install from Source

```bash
git clone https://github.com/im-customers-arm/spdx-xsafety-sbom.git
cd spdx-xsafety-sbom
uv sync
```

### Install with Validation Support

```bash
uv sync --extra validation
```

### Install with Native StrictDoc Parsing (Recommended)

When installed with the `strictdoc` extra, the tool uses StrictDoc's native library
for parsing `.sdoc` files directly, eliminating the need for JSON export:

```bash
uv sync --extra strictdoc
```

This enables:
- **Native `.sdoc` parsing** using StrictDoc's `SDReader` (tree-sitter based)
- **Native source traceability** using StrictDoc's `SourceFileTraceabilityReader`
- Automatic fallback to JSON/regex parsing when StrictDoc is not installed

### Install All Extras (Development)

```bash
uv sync --extra all
```

## Usage

### Generate Design SBOM

From StrictDoc JSON export (default):

```bash
uv run spdx-xsafety-sbom generate \
    --source-root /path/to/project \
    --strictdoc-dir /path/to/strictdoc-json \
    --output design-sbom.json
```

From native `.sdoc` files (when installed with `strictdoc` extra):

```bash
uv run spdx-xsafety-sbom generate \
    --source-root /path/to/project \
    --strictdoc-dir /path/to/strictdoc-docs \
    --output design-sbom.json
```

The tool automatically detects whether to use native parsing (for `.sdoc` files)
or JSON parsing based on the file types found in the directory.

### Validate Existing SBOM

```bash
uv run spdx-xsafety-sbom validate design-sbom.json
```

### With SHACL Validation

```bash
uv run spdx-xsafety-sbom validate design-sbom.json \
    --shacl-shapes spdx_extensions/shacl/safety-shapes.ttl
```

## Output Format

The generated SBOM is in **JSON-LD** format with SPDX 3.0.1 structure:

```json
{
  "@context": [
    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    { "xSafety": "https://example.org/spdx-extensions/xSafety/" }
  ],
  "@graph": [
    {
      "@type": "SpdxDocument",
      "spdxId": "urn:spdx:cam:document",
      "name": "Design SBOM",
      ...
    },
    {
      "@type": "Bundle",
      "spdxId": "urn:spdx:cam:SSR-001",
      "name": "[SSR] Software Safety Requirement",
      "extension": [{
        "type": "xSafety:SafetyRequirementExtension",
        "xSafety:requirementType": "softwareSafetyRequirement",
        "xSafety:safetyIntegrityLevel": "asilD"
      }]
    }
  ]
}
```

## Project Structure

```
spdx-xsafety-sbom/
├── pyproject.toml              # UV-compatible project configuration
├── uv.lock                     # UV lock file (auto-generated)
├── README.md
├── AGENTS.md                   # Agent instructions (UV-only)
├── src/
│   └── spdx_xsafety_sbom/      # Main package
│       ├── __init__.py
│       ├── cli.py              # CLI entry point (click-based)
│       ├── generator.py        # Main SBOM generation logic
│       ├── strictdoc_parser.py # StrictDoc parsing (native + JSON fallback)
│       ├── source_scanner.py   # @sdoc marker scanning (native + regex)
│       ├── spdx_builder.py     # SPDX 3.0.1 element construction
│       ├── relationships.py    # Relationship type mapping
│       └── validation/
│           ├── __init__.py
│           ├── spdx_validator.py   # SPDX JSON-LD validation
│           └── shacl_validator.py  # SHACL shape validation
├── spdx_extensions/            # xSafety extension specs (from spdx_diff)
│   ├── specs/
│   │   └── safety-profile.md
│   ├── contexts/
│   │   └── safety-context.jsonld
│   └── shacl/
│       └── safety-shapes.ttl
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_generator.py
    └── fixtures/
        └── sample_strictdoc/
```

## Development

### Running Tests

```bash
uv run pytest -v
```

### Running Tests with Coverage

```bash
uv run pytest --cov=spdx_xsafety_sbom --cov-report=html
```

### Linting and Formatting

```bash
uv run ruff check spdx_xsafety_sbom/
uv run ruff format spdx_xsafety_sbom/
```

### Type Checking

```bash
uv run mypy spdx_xsafety_sbom/ --strict
```

## Reference Specifications

### SPDX 3.0.1

- [SPDX 3.0.1 Specification](https://spdx.github.io/spdx-spec/v3.0.1/)
- [Bundle Class](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/Bundle/)
- [Relationship Types](https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/)

### xSafety Extension

- **Namespace**: `https://example.org/spdx-extensions/xSafety/`
- **Version**: 2.1.0
- **Spec**: See `spdx_extensions/specs/safety-profile.md`

### Key Relationship Types

| RelationshipType | Description |
|-----------------|-------------|
| `descendantOf` | The `from` Element is a descendant of each `to` Element |
| `hasSpecification` | Every `to` Element is a specification for the `from` Element |
| `hasTestCase` | Every `to` Element is a test case for the `from` Element |
| `hasEvidence` | Every `to` Element is considered as evidence for the `from` Element |
| `testedOn` | The `from` Element has been tested on the `to` Element(s) |

## License

MIT License - See LICENSE file for details.
