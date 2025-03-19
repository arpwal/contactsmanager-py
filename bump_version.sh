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

# Get current version
CURRENT_VERSION=$(grep -oP "__version__ = ['\"]\\K[^'\"]*" $INIT_FILE)
echo "Current version: $CURRENT_VERSION"
echo "New version: $NEW_VERSION"

# Update the version in the file
sed -i.bak "s/__version__ = ['\"]$CURRENT_VERSION['\"]/__version__ = '$NEW_VERSION'/" $INIT_FILE
rm -f "${INIT_FILE}.bak"

echo "Version updated successfully!"
echo "Don't forget to commit and push the changes:"
echo "git add $INIT_FILE"
echo "git commit -m \"Bump version to $NEW_VERSION\""
echo "git push origin main" 