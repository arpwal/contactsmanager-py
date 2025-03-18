# ContactsManager Python SDK

A Python SDK for the ContactsManager API that handles authentication and token generation.

## Installation

```bash
pip install contactsmanager-py
```

## Usage

```python
from contactsmanager_py import ContactsManagerClient

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

## Requirements

- Python 3.7+
- PyJWT>=2.0.0

## License

MIT License 