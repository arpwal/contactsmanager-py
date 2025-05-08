#!/bin/bash
# Script to run integration tests for the ContactsManager Python SDK

# Check if .env file exists and load it
if [ -f ".env" ]; then
    echo "Loading environment variables from .env file"
    export $(grep -v '^#' .env | xargs)
fi

# Check if we have the necessary configuration
if [ -z "$TEST_CONFIG" ]; then
    echo "Warning: No configuration found. Tests requiring credentials will be skipped."
    echo "Please set the TEST_CONFIG environment variable with JSON configuration"
fi

# Run the integration tests
python -m contactsmanager.integration_tests.run_tests
