#!/bin/bash
# Script to bump version number in __init__.py

# Check if a version parameter is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 0.1.1"
    exit 1
fi

NEW_VERSION=$1
INIT_FILE="contactsmanager/__init__.py"

# Check if the file exists
if [ ! -f "$INIT_FILE" ]; then
    echo "Error: $INIT_FILE does not exist"
    exit 1
fi

# Get current version - using a more portable grep approach
CURRENT_VERSION=$(grep "__version__" "$INIT_FILE" | sed -E "s/__version__ = ['\"]([^'\"]*)['\"].*/\1/")
echo "Current version: $CURRENT_VERSION"
echo "New version: $NEW_VERSION"

# Update the version in the file - works on both macOS and Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/__version__ = ['\"]$CURRENT_VERSION['\"]/__version__ = '$NEW_VERSION'/" "$INIT_FILE"
else
    # Linux and others
    sed -i "s/__version__ = ['\"]$CURRENT_VERSION['\"]/__version__ = '$NEW_VERSION'/" "$INIT_FILE"
fi

echo "Version updated successfully!"
echo "Don't forget to commit and push the changes:"
echo "git add $INIT_FILE"
echo "git commit -m \"Bump version to $NEW_VERSION\""
echo "git push origin main" 