"""
SPDX xSafety SBOM Generator

A tool for generating SPDX 3.0.1 Design SBOMs with xSafety extension
from StrictDoc requirements and source code.
"""

__version__ = "0.1.0"
__author__ = "ARM"

from spdx_xsafety_sbom.generator import generate_design_sbom

__all__ = ["generate_design_sbom", "__version__"]
