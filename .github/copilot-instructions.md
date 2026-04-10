
# Copilot Instructions for spdx-xsafety-sbom

You are assisting on spdx-xsafety-sbom, a Python tool that generates SPDX 3.0.1 JSON-LD Design SBOMs with xSafety extensions.

## Required Tooling and Environment

- Use Python 3.12+ (CI validates 3.12 and 3.13).
- Use UV for dependency and command execution.
- Prefer `uv run <command>` for all project tooling.
- Use `uv sync --dev` before local development checks.

## Dependency Rules (Important)

- Keep runtime dependencies in `[project.dependencies]`.
- Keep CI/dev tooling in `[dependency-groups].dev` (Ruff, MyPy, Pytest, etc.).
- Keep optional feature dependencies in `[project.optional-dependencies]`.
- Do not switch this repository to pip/poetry/conda workflows.

## Local Validation Before PR

Run this sequence and require exit code 0 from each step:

```bash
uv sync --dev
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/
uv run pytest tests/ -v --tb=short
uv build
uvx twine check dist/*
uv run spdx-xsafety-sbom generate tests/fixtures/sdoc -o test-output.json --no-source-scan
uv run spdx-xsafety-sbom validate test-output.json
```

If `twine` is missing locally, add it as a dev dependency with `uv add --dev twine`.

## CI Pipeline Model

The workflow in `.github/workflows/ci.yml` runs:

1. Lint (`ruff check` + `ruff format --check`) on Ubuntu, Python 3.12.
2. Type check (`mypy src/`) on Ubuntu, Python 3.12.
3. Tests on Ubuntu/Windows/macOS for Python 3.12 and 3.13.
4. Build (`uv build`, package checks) after lint/type/test pass.
5. Integration tests (CLI smoke and SBOM generate/validate) after build.

## Python and Testing Standards

- Follow Ruff formatting and lint rules from `pyproject.toml`.
- Keep function signatures fully type hinted; MyPy strict mode must pass.
- Use `Path` APIs for cross-platform path behavior.
- Add or update pytest coverage for every behavior change.
- Prefer fixtures to avoid repeated parser setup in tests.
- Keep assertions aligned to domain semantics (parent vs child traceability direction).

## Architecture Context

- Input format 1: StrictDoc `.sdoc`.
- Input format 2: Sphinx-Needs `needs.json` export.
- Both parsers normalize to `dict[str, StrictDocNode]` for downstream generation.
- Generator output must remain valid SPDX 3.0.1 JSON-LD and include `@context` and `@graph`.

## Change Guidelines

- Parser changes should preserve parity between StrictDoc and Sphinx-Needs where data overlaps.
- When modifying fixtures under `tests/fixtures/`, update affected tests in the same change.
- CLI changes must include help/behavior test updates.
- Validation changes should include tests in `tests/test_validator.py`.

## Quick Troubleshooting

- Lint mismatch: run `uv sync --dev`, then `uv run ruff format src/ tests/`.
- Type errors: run `uv run mypy src/` and add/fix type hints.
- Cross-platform failures: check path assumptions and newline handling.
- Schema validation imports: ensure validation extras are installed when needed.

## Key Files

- `pyproject.toml`
- `.github/workflows/ci.yml`
- `src/spdx_xsafety_sbom/generator.py`
- `src/spdx_xsafety_sbom/sphinxneeds_parser.py`
- `src/spdx_xsafety_sbom/strictdoc_parser.py`
- `src/spdx_xsafety_sbom/validation/spdx_validator.py`
