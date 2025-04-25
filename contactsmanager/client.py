import jwt
import time
import uuid
import hmac
import hashlib
from typing import Dict, Any, Optional, Union


class ContactsManagerClient:
    """Client for the ContactsManager API that handles authentication and token generation."""

    def __init__(self, api_key: str, api_secret: str, org_id: str):
        """
        Initialize the ContactsManager client.

        Args:
            api_key: The API key for the organization
            api_secret: The API secret for the organization
            org_id: The organization ID
        """
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key is required and must be a string")
        if not api_secret or not isinstance(api_secret, str):
            raise ValueError("API secret is required and must be a string")
        if not org_id or not isinstance(org_id, str):
            raise ValueError("Organization ID is required and must be a string")

        self.api_key = api_key
        self.api_secret = api_secret
        self.org_id = org_id
        self.webhook_secret = None

    def generate_token(
        self,
        user_id: str,
        device_info: Optional[Dict[str, Any]] = None,
        expiration_seconds: int = 86400,
    ) -> Dict[str, Any]:
        """
        Generate a JWT token for the specified user.

        Args:
            user_id: The ID of the user to generate a token for
            device_info: Optional dictionary containing device metadata
            expiration_seconds: Number of seconds until the token expires (default: 24 hours)

        Returns:
            Dict containing the token and expiration timestamp
        """
        if not user_id or not isinstance(user_id, str):
            raise ValueError("User ID is required and must be a string")

        if device_info is not None and not isinstance(device_info, dict):
            raise ValueError("Device info must be a dictionary if provided")

        # Current timestamp
        now = int(time.time())

        # Create token payload
        payload = {
            "iss": self.org_id,  # Issuer
            "org_id": self.org_id,  # Organization ID
            "api_key": self.api_key,  # API key (identifies the organization)
            "user_id": user_id,  # End user ID
            "device_info": device_info or {},  # Device metadata
            "jti": str(uuid.uuid4()),  # Unique token ID
            "iat": now,  # Issued at time
            "exp": now + expiration_seconds,  # Expiration time
        }

        # Generate the JWT token signed with the API secret
        token = jwt.encode(payload, self.api_secret, algorithm="HS256")

        return {"token": token, "expires_at": payload["exp"]}

    def set_webhook_secret(self, webhook_secret: str) -> None:
        """
        Set the webhook secret for verifying webhook signatures.

        Args:
            webhook_secret: The webhook secret from your dashboard
        """
        if not webhook_secret or not isinstance(webhook_secret, str):
            raise ValueError("Webhook secret is required and must be a string")

        self.webhook_secret = webhook_secret

    def verify_webhook_signature(
        self, payload: Union[bytes, str, Dict], signature: str
    ) -> bool:
        """
        Verify the signature of a webhook request.

        Args:
            payload: The raw request body (bytes, string, or parsed JSON)
            signature: The X-Webhook-Signature header value

        Returns:
            bool: True if signature is valid, False otherwise
        """
        if not self.webhook_secret:
            raise ValueError("Webhook secret not set. Call set_webhook_secret() first.")

        try:
            # Parse the signature header
            components = {}
            for part in signature.split(","):
                key, value = part.split("=")
                components[key] = value

            if "t" not in components or "v1" not in components:
                return False

            timestamp = components["t"]
            given_signature = components["v1"]

            # Check if the timestamp is not too old (15 minute window)
            current_time = int(time.time())
            if current_time - int(timestamp) > 900:  # 15 minutes
                return False

            # Convert payload to string if it's a dictionary
            if isinstance(payload, dict):
                import json

                payload_str = json.dumps(payload)
            elif isinstance(payload, bytes):
                payload_str = payload.decode("utf-8")
            else:
                payload_str = str(payload)

            # Compute the expected signature
            signed_content = f"{timestamp}.{payload_str}"
            expected_signature = hmac.new(
                self.webhook_secret.encode("utf-8"),
                signed_content.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            # Compare signatures (constant-time comparison)
            return hmac.compare_digest(given_signature, expected_signature)
        except Exception as e:
            # Log the error in a production environment
            print(f"Error verifying signature: {str(e)}")
            return False
