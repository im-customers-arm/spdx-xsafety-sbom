# Contributing to spdx-xsafety-sbom

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites
- Python 3.12 or higher
- [UV package manager](https://docs.astral.sh/uv/) (required)
- Git

### Clone and Setup

```bash
git clone https://github.com/im-customers-arm/spdx-xsafety-sbom.git
cd spdx-xsafety-sbom

# Install UV if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh  # Unix/macOS
# or
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows

# Install dependencies for local development
uv sync --dev

# Optional: include validation extras (pyshacl, rdflib, etc.)
uv sync --extra validation
```

## Development Workflow

### Running Tests

```bash
# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=spdx_xsafety_sbom --cov-report=html

# Run specific test file
uv run pytest tests/test_generator.py -v
```

### Code Quality

```bash
# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/

# Type check
uv run mypy src/
```

### Testing Your Changes

```bash
# Test CLI locally
uv run spdx-xsafety-sbom --help

# Generate test SBOM
uv run spdx-xsafety-sbom generate tests/fixtures/sdoc -o test.json --no-source-scan
```

## Pull Request Process

1. **Fork the repository** and create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style:
   - Follow PEP 8 (enforced by Ruff)
   - Add type hints
   - Write docstrings for public functions/classes
   - Keep functions focused and testable

3. **Add tests** for new functionality:
   - Unit tests in `tests/test_*.py`
   - Use fixtures from `tests/conftest.py`
   - Aim for >80% code coverage

4. **Update documentation**:
   - Update `README.md` if adding features
   - Add docstrings to new functions
   - Update examples if CLI changes

5. **Run checks locally**:
   ```bash
   uv run ruff check src/ tests/
   uv run ruff format src/ tests/
   uv run mypy src/
   uv run pytest -v
   ```

6. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add SBOM comparison feature
   
   - Add compare command to CLI
   - Implement diff algorithm
   - Add tests for comparison logic"
   ```

7. **Push and create PR**:
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a Pull Request on GitHub with:
   - Clear description of changes
   - Link to related issues
   - Screenshots/examples if relevant

## Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `ci:` CI/CD changes
- `chore:` Maintenance tasks

## Code Style

### Python Style
- Use Ruff for linting and formatting (configured in `pyproject.toml`)
- Follow type hints (checked by mypy)
- Maximum line length: 100 characters
- Use meaningful variable names
- Keep functions under 50 lines when possible

### Module Organization
```python
"""
Module docstring explaining purpose.
"""

from __future__ import annotations  # For forward references

import stdlib_imports
import third_party_imports

from project_imports import something

# Constants
CONSTANT_NAME = "value"

# Classes and functions
```

### Testing Style
```python
def test_feature_description():
    """Test that feature works correctly."""
    # Arrange
    input_data = create_test_data()
    
    # Act
    result = function_under_test(input_data)
    
    # Assert
    assert result.property == expected_value
```

## Documentation

- Write clear docstrings using Google style:
  ```python
  def function(param1: str, param2: int) -> bool:
      """
      Short description.
      
      Longer description if needed.
      
      Args:
          param1: Description of param1
          param2: Description of param2
          
      Returns:
          Description of return value
          
      Raises:
          ValueError: When invalid input
      """
  ```

## Adding New Features

### New CLI Command
1. Add command function in `src/spdx_xsafety_sbom/cli.py`
2. Use Click decorators for options/arguments
3. Use Rich for beautiful output
4. Add tests in `tests/` (e.g., a new `test_cli.py` module)
5. Update README.md usage section

### New SPDX Element Type
1. Add builder method in `src/spdx_xsafety_sbom/spdx_builder.py`
2. Add model in `src/spdx_xsafety_sbom/models.py` if needed
3. Update parser to recognize new type
4. Add tests
5. Update documentation

### New Validation
1. Add validator in `src/spdx_xsafety_sbom/validation/`
2. Integrate into main validation flow
3. Add tests with valid and invalid examples
4. Update CLI to support new validation

## Questions?

- Open an issue for questions
- Check existing issues and PRs first
- Join discussions in GitHub Discussions (if enabled)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
