#!/bin/bash
# Script to bump version number in __init__.py

INIT_FILE="contactsmanager/__init__.py"

# Check if the file exists
if [ ! -f "$INIT_FILE" ]; then
    echo "Error: $INIT_FILE does not exist"
    exit 1
fi

# Get current version - using a more portable grep approach
CURRENT_VERSION=$(grep "__version__" "$INIT_FILE" | sed -E "s/__version__ = ['\"]([^'\"]*)['\"].*/\1/")
echo "Current version: $CURRENT_VERSION"

# Check if a version parameter is provided or auto-increment minor version
if [ "$#" -eq 1 ]; then
    NEW_VERSION=$1
else
    # Auto-increment the minor version
    # Parse the current version (assuming semantic versioning: MAJOR.MINOR.PATCH)
    IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
    MAJOR=${VERSION_PARTS[0]}
    MINOR=${VERSION_PARTS[1]}
    PATCH=${VERSION_PARTS[2]:-0}  # Default to 0 if not present

    # Increment minor version
    NEW_MINOR=$((MINOR + 1))
    NEW_VERSION="$MAJOR.$NEW_MINOR.0"  # Reset patch version to 0
    
    echo "No version specified, auto-incrementing minor version."
fi

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