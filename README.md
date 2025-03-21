# ContactsManager Python SDK

A Python SDK for the ContactsManager API that handles authentication and token generation.

## Installation

```bash
pip install contactsmanager
```

## Usage

```python
from contactsmanager import ContactsManagerClient

# Initialize the client
client = ContactsManagerClient(
    api_key="your_api_key",
    api_secret="your_api_secret",
    org_id="your_org_id"
)

# Generate a token for a user
token_response = client.generate_token(
    user_id="user123",
    device_info={  # Optional
        "device_type": "mobile",
        "os": "iOS",
        "app_version": "1.0.0"
    }
)

print(f"Token: {token_response['token']}")
print(f"Expires at: {token_response['expires_at']}")
```

## Features

- Simple API for generating JWT tokens
- Type hints for better IDE support
- Comprehensive test coverage
- Support for custom token expiration

## Advanced Usage

### Custom Token Expiration

By default, tokens expire after 24 hours (86400 seconds). You can customize this:

```python
# Generate a token that expires in 1 hour
token_response = client.generate_token(
    user_id="user123",
    expiration_seconds=3600  # 1 hour
)
```

## Requirements

- Python 3.8+
- PyJWT>=2.0.0

## Development

### Setting up development environment

```bash
# Clone the repository
git clone https://github.com/arpwal/contactmanager.git
cd contactmanager/sdk/py

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Releasing new versions

The SDK uses an automated process for releases:

1. Update the version in `contactsmanager/__init__.py` using the provided script:
   ```bash
   ./bump_version.sh 0.1.1
   ```

2. Commit and push the change to the main branch:
   ```bash
   git add contactsmanager/__init__.py
   git commit -m "Bump version to 0.1.1"
   git push origin main
   ```

3. The GitHub Actions workflow will:
   - Run all tests across multiple Python versions
   - Create a new GitHub release with the version tag
   - Build and publish the package to PyPI

Alternatively, you can manually create a new release by:

1. Creating and pushing a git tag:
   ```bash
   git tag -a v0.1.1 -m "Release version 0.1.1"
   git push origin v0.1.1
   ```

2. The GitHub Actions workflow will handle the rest

## License

MIT License 