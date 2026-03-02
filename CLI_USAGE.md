# SPDX xSafety SBOM CLI Usage

## Installation

1. Install [uv](https://astral.sh/uv/):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```
2. Install dependencies:
   ```bash
   uv sync --dev
   ```

## Basic Command

Generate an SPDX 3.0.1 Design SBOM from a StrictDoc project:

```bash
uv run spdx-xsafety-sbom generate <STRICTDOC_PATH> -o <OUTPUT_FILE> --name "<SBOM Name>" --org "<Organization>"
```

- `<STRICTDOC_PATH>`: Path to the directory containing StrictDoc `.sdoc` files
- `-o, --output`: Output SBOM file (default: `design-sbom.json`)
- `--name`: Name for the SBOM document
- `--org`: Organization name (optional)

**Example:**
```bash
uv run spdx-xsafety-sbom generate "D:/GITHUB/ARM/arm-critical-app-monitoring/docs/strictdoc" -o cam-sbom.json --name "CAM Design SBOM" --org "ARM"
```

## Other Options

- `--source-root <DIR>`: Root directory for source code scanning (optional, auto-detected from git root when omitted)
- `--prefix <PREFIX>`: Custom SPDX ID prefix (default: `urn:spdx:example:`)
- `--no-source-scan`: Disable @sdoc marker scanning
- `--no-validate`: Disable output validation

## Validation

Validate an existing SBOM file:
```bash
uv run spdx-xsafety-sbom validate <SBOM_FILE>
```

To run SHACL shape validation in addition to structure checks:
```bash
uv run spdx-xsafety-sbom validate <SBOM_FILE> --shacl
```

Install validation extras first:
```bash
uv sync --extra validation
```

## Help

Show all options:
```bash
uv run spdx-xsafety-sbom --help
uv run spdx-xsafety-sbom generate --help
```

## Notes
- Always use `uv run` to execute commands.
- The CLI requires a local path to StrictDoc files (no git URL support).
- Output and validation warnings will be shown in the terminal.
