#!/bin/bash
# Script to upload package to PyPI using an API token

# Check if PYPI_API_TOKEN is provided
if [ -z "$PYPI_API_TOKEN" ]; then
    echo "Error: PYPI_API_TOKEN environment variable is not set"
    echo "Usage: PYPI_API_TOKEN=your_token ./upload_to_pypi.sh"
    exit 1
fi

# Clean up previous builds
rm -rf dist/ build/ *.egg-info

# Build the package
python -m build

# Check the distributions
twine check dist/*

# Upload to PyPI with token auth
TWINE_USERNAME="__token__" TWINE_PASSWORD="$PYPI_API_TOKEN" twine upload dist/*

echo "Upload complete!" 