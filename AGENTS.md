# Agent Instructions (CODEX)

## Package and Dependency Management

**CRITICAL: Always use UV for all package and dependency management operations.**

UV is the required package manager for this repository. Never use pip, conda, poetry, or any other package manager.

### Installation and Setup

- **Install UV**: Use `curl -LsSf https://astral.sh/uv/install.sh | sh` or follow the official UV installation guide
- **Verify installation**: `uv --version`
- **Install dependencies**: Always use `uv sync` to install dependencies from `uv.lock` and `pyproject.toml`
- **Install project in development mode**: Use `uv sync --dev` to install the project and all development dependencies

### Common UV Commands

**Installing dependencies:**
```bash
uv sync                    # Install all dependencies from uv.lock
uv sync --dev              # Include development dependencies
uv sync --extra validation # Install validation extras
uv sync --extra all        # Install all extras
```

**Adding dependencies:**
```bash
uv add <package>           # Add a runtime dependency
uv add --dev <package>     # Add a development dependency
uv add --optional <package> # Add an optional dependency
```

**Removing dependencies:**
```bash
uv remove <package>        # Remove a dependency
```

**Running commands:**
```bash
uv run <command>                  # Run a command in the UV environment
uv run spdx-xsafety-sbom ...      # Run CLI tool
uv run pytest                     # Run tests
uv run python script.py           # Run Python scripts
```

**Updating dependencies:**
```bash
uv lock                    # Update uv.lock file
uv sync                    # Sync with updated lock file
```

**Building packages:**
```bash
uv build                   # Build the package
```

### Project-Specific Usage

For spdx-xsafety-sbom project:

```bash
# Install dependencies
cd spdx-xsafety-sbom
uv sync --dev

# Run CLI tool
uv run spdx-xsafety-sbom generate \
    --source-root /path/to/repo \
    --strictdoc-dir /path/to/strictdoc-json \
    --output design-sbom.json

# Run tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=spdx_xsafety_sbom --cov-report=term-missing

# Type checking
uv run mypy spdx_xsafety_sbom/ --strict

# Linting
uv run ruff check spdx_xsafety_sbom/
uv run ruff format spdx_xsafety_sbom/
```

### When Making Changes

1. **Before modifying dependencies**: Ensure you're in the `spdx-xsafety-sbom/` directory
2. **After adding/removing dependencies**: Always run `uv lock` to update the lock file
3. **Before committing**: Verify `uv.lock` is updated and synced
4. **In scripts and documentation**: Always use `uv run` prefix for commands, never bare `python`, `pytest`, or `spdx-xsafety-sbom`

### Prohibited Commands

**NEVER use:**
- `pip install ...` - Use `uv add` instead
- `pip uninstall ...` - Use `uv remove` instead
- `python -m pip ...` - Use `uv` commands instead
- `poetry add ...` - Use `uv add` instead
- `conda install ...` - Use `uv add` instead
- Bare `python script.py` - Use `uv run python script.py` instead
- Bare `pytest` - Use `uv run pytest` instead
- Bare `spdx-xsafety-sbom ...` - Use `uv run spdx-xsafety-sbom ...` instead

### Environment Variables

UV respects standard Python environment variables, but prefer UV's built-in mechanisms:
- Use `uv sync` instead of manually managing virtual environments
- UV automatically creates and manages virtual environments

### Troubleshooting

- **Lock file conflicts**: Run `uv lock --upgrade` to regenerate the lock file
- **Dependency resolution issues**: Check `pyproject.toml` for version constraints
- **Virtual environment issues**: UV manages this automatically; if problems persist, delete `.venv` and run `uv sync` again

---

**Remember**: UV is fast, reliable, and reproducible. Using it ensures consistent environments across all developers and CI/CD systems.
