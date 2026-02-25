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

### Option 1: Pre-built Executables (Recommended for CI/CD)

Download standalone executables from the [GitHub Releases](https://github.com/im-customers-arm/spdx-xsafety-sbom/releases) page. No Python installation required.

| Platform | Download |
|----------|----------|
| Linux (x64) | `spdx-xsafety-sbom-vX.Y.Z-linux-x64` |
| Windows (x64) | `spdx-xsafety-sbom-vX.Y.Z-windows-x64.exe` |
| macOS (ARM64) | `spdx-xsafety-sbom-vX.Y.Z-macos-arm64` |

```bash
# Example: Download and run on Linux
curl -LO https://github.com/im-customers-arm/spdx-xsafety-sbom/releases/latest/download/spdx-xsafety-sbom-v0.1.0-linux-x64
chmod +x spdx-xsafety-sbom-v0.1.0-linux-x64
./spdx-xsafety-sbom-v0.1.0-linux-x64 generate --help
```

### Option 2: Install from Source

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

StrictDoc is a core dependency; native `.sdoc` parsing is always available.

### Install All Extras (Development)

```bash
uv sync --extra all
```

## Usage

### Generate Design SBOM

Point to the StrictDoc directory (containing `.sdoc` files). Source root is optional and can be auto-detected from the git root:

```bash
uv run spdx-xsafety-sbom generate /path/to/strictdoc -o design-sbom.json
```

With explicit source root for `@sdoc` marker scanning:

```bash
uv run spdx-xsafety-sbom generate /path/to/strictdoc -s /path/to/project -o design-sbom.json
```

The tool uses hybrid parsing: native `.sdoc` parsing by default, with JSON fallback when custom grammars (`.sgra` or `strictdoc.toml`) are detected.

### Validate Existing SBOM

```bash
uv run spdx-xsafety-sbom validate design-sbom.json
```

### With SHACL Validation

```bash
uv run spdx-xsafety-sbom validate design-sbom.json --shacl
```

Requires `uv sync --extra validation` (pyshacl, rdflib). SHACL shapes are loaded from `spdx_extensions/shacl/safety-shapes.ttl`.

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
├── ruff.toml                   # Ruff lint/format configuration
├── README.md
├── AGENTS.md                   # Agent instructions (UV-only)
├── src/
│   └── spdx_xsafety_sbom/      # Main package
│       ├── __init__.py
│       ├── cli.py              # CLI entry point (click-based)
│       ├── constants.py        # SPDX/xSafety vocabularies
│       ├── generator.py        # Main SBOM generation logic
│       ├── models.py           # Data classes (StrictDocNode, RangeLink)
│       ├── paths.py            # Path utilities (frozen/dev)
│       ├── relationships.py    # Relationship type mapping
│       ├── source_scanner.py   # @sdoc marker scanning (native + regex)
│       ├── spdx_builder.py     # SPDX 3.0.1 element construction
│       ├── strictdoc_parser.py # StrictDoc parsing (native + JSON fallback)
│       └── validation/
│           ├── __init__.py
│           ├── spdx_validator.py   # SPDX JSON-LD validation
│           └── shacl_validator.py  # SHACL shape validation
├── scripts/
│   ├── build_executable.py     # PyInstaller build script
│   └── spdx-xsafety-sbom.spec  # PyInstaller spec
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
    ├── test_source_scanner.py
    ├── test_spdx_builder.py
    ├── test_strictdoc_parser.py
    ├── test_validator.py
    └── fixtures/
        ├── sample-sbom.json
        ├── sdoc/               # .sdoc fixtures
        ├── source/             # Source file fixtures
        └── strictdoc-export/   # JSON export fixtures
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

Ruff uses `ruff.toml` at project root when present. Otherwise `pyproject.toml` [tool.ruff] applies:

```bash
uv run ruff check spdx_xsafety_sbom/
uv run ruff format spdx_xsafety_sbom/
```

### Type Checking

```bash
uv run mypy spdx_xsafety_sbom/ --strict
```

### Building Executables

To build a standalone executable for your platform:

```bash
uv sync --dev
uv run python scripts/build_executable.py
```

The executable will be created in `dist/` with platform-specific naming.

## Releasing

Releases are automated via GitHub Actions. To create a new release:

1. Update version in [pyproject.toml](pyproject.toml) and [src/spdx_xsafety_sbom/__init__.py](src/spdx_xsafety_sbom/__init__.py)
2. Commit the version bump
3. Create and push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow will automatically:
- Build executables for Linux, Windows, and macOS
- Create a GitHub Release with all artifacts and checksums
- Publish to PyPI (for non-prerelease versions)

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
