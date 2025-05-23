import unittest
import time
import jwt
import json
import hmac
import hashlib
from unittest.mock import patch, MagicMock
from contactsmanager import ContactsManagerClient
from contactsmanager.types import UserInfo, DeviceInfo
from contactsmanager.server_api import ServerAPIError


class TestContactsManagerClient(unittest.TestCase):
    def setUp(self):
        self.api_key = "test_api_key"
        self.api_secret = "test_api_secret"
        self.org_id = "test_org_id"
        self.client = ContactsManagerClient(
            api_key=self.api_key, api_secret=self.api_secret, org_id=self.org_id
        )

    def test_init_with_valid_params(self):
        """Test that the client initializes correctly with valid parameters."""
        self.assertEqual(self.client.api_key, self.api_key)
        self.assertEqual(self.client.api_secret, self.api_secret)
        self.assertEqual(self.client.org_id, self.org_id)

    def test_init_with_invalid_params(self):
        """Test that the client raises ValueError with invalid parameters."""
        with self.assertRaises(ValueError):
            ContactsManagerClient(
                api_key="", api_secret=self.api_secret, org_id=self.org_id
            )

        with self.assertRaises(ValueError):
            ContactsManagerClient(
                api_key=self.api_key, api_secret="", org_id=self.org_id
            )

        with self.assertRaises(ValueError):
            ContactsManagerClient(
                api_key=self.api_key, api_secret=self.api_secret, org_id=""
            )

        with self.assertRaises(ValueError):
            ContactsManagerClient(
                api_key=123, api_secret=self.api_secret, org_id=self.org_id
            )

    def test_generate_token_with_valid_params(self):
        """Test that generate_token works with valid parameters."""
        user_id = "test_user_id"
        device_info = {"device": "web", "browser": "chrome"}

        # Mock UUID and time for deterministic tests
        with patch("uuid.uuid4", return_value="mock-uuid"), patch(
            "time.time", return_value=1000000
        ):

            token_data = self.client.generate_token(user_id, device_info)

            # Verify token is returned
            self.assertIn("token", token_data)
            self.assertIn("expires_at", token_data)
            self.assertEqual(token_data["expires_at"], 1000000 + 86400)

            # Decode and verify token contents without verifying expiration
            decoded = jwt.decode(
                token_data["token"],
                self.api_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},  # Skip expiration verification
            )

            self.assertEqual(decoded["iss"], self.org_id)
            self.assertEqual(decoded["org_id"], self.org_id)
            self.assertEqual(decoded["api_key"], self.api_key)
            self.assertEqual(decoded["user_id"], user_id)
            self.assertEqual(decoded["device_info"], device_info)
            self.assertEqual(decoded["jti"], "mock-uuid")
            self.assertEqual(decoded["iat"], 1000000)
            self.assertEqual(decoded["exp"], 1000000 + 86400)

    def test_generate_token_with_custom_expiration(self):
        """Test generate_token with custom expiration time."""
        user_id = "test_user_id"
        expiration = 3600  # 1 hour

        with patch("time.time", return_value=1000000):
            token_data = self.client.generate_token(
                user_id, expiration_seconds=expiration
            )
            self.assertEqual(token_data["expires_at"], 1000000 + expiration)

    def test_generate_token_with_invalid_params(self):
        """Test that generate_token raises ValueError with invalid parameters."""
        with self.assertRaises(ValueError):
            self.client.generate_token(user_id="")

        with self.assertRaises(ValueError):
            self.client.generate_token(user_id=123)

        with self.assertRaises(ValueError):
            self.client.generate_token(user_id="test_user", device_info="not_a_dict")

    def test_create_user_with_valid_params(self):
        """Test create_user with valid parameters."""
        user_info = UserInfo(
            user_id="test_user_123",
            full_name="Test User",
            email="test@example.com",
            phone="+1234567890",
        )
        device_info = DeviceInfo(device_type="mobile", os="iOS", app_version="1.0.0")

        # Mock the generate_token method
        mock_token_data = {"token": "mock_token", "expires_at": 1234567890}

        # Mock the ServerAPI and its create_user method
        mock_response = MagicMock()
        mock_response.status = "success"
        mock_response.data = MagicMock()
        mock_response.data.token = MagicMock()
        mock_response.data.token.token = "new_token"
        mock_response.data.token.expires_at = 1234567890
        mock_response.data.user = MagicMock()
        mock_response.data.created = True

        with patch.object(
            self.client, "generate_token", return_value=mock_token_data
        ) as mock_gen_token, patch(
            "contactsmanager.client.ServerAPI"
        ) as mock_server_api_class:

            mock_server_api = mock_server_api_class.return_value
            mock_server_api.create_user.return_value = mock_response

            result = self.client.create_user(user_info, device_info, 3600)

            # Verify generate_token was called correctly
            mock_gen_token.assert_called_once_with(
                user_id="test_user_123",
                device_info=device_info,
                expiration_seconds=3600,
            )

            # Verify ServerAPI was initialized with the token
            mock_server_api_class.assert_called_once_with("mock_token")

            # Verify create_user was called on ServerAPI
            mock_server_api.create_user.assert_called_once_with(
                uid="test_user_123",
                user_info=user_info,
                device_info=device_info,
                expiry_seconds=3600,
            )

            # Verify the result
            self.assertEqual(result, mock_response)

    def test_create_user_with_invalid_user_info(self):
        """Test create_user with invalid user_info parameter."""
        # Test with None
        with self.assertRaises(ValueError) as context:
            self.client.create_user(None)
        self.assertIn(
            "user_info is required and must be a UserInfo object",
            str(context.exception),
        )

        # Test with wrong type
        with self.assertRaises(ValueError) as context:
            self.client.create_user({"user_id": "test"})
        self.assertIn(
            "user_info is required and must be a UserInfo object",
            str(context.exception),
        )

    def test_create_user_server_api_error(self):
        """Test create_user when ServerAPI raises an error."""
        user_info = UserInfo(
            user_id="test_user_123", full_name="Test User", email="test@example.com"
        )

        mock_token_data = {"token": "mock_token", "expires_at": 1234567890}

        with patch.object(
            self.client, "generate_token", return_value=mock_token_data
        ), patch("contactsmanager.client.ServerAPI") as mock_server_api_class:

            mock_server_api = mock_server_api_class.return_value
            mock_server_api.create_user.side_effect = ServerAPIError("API Error", 500)

            with self.assertRaises(ServerAPIError):
                self.client.create_user(user_info)

    def test_delete_user_with_valid_params(self):
        """Test delete_user with valid parameters."""
        uid = "test_user_123"

        # Mock the generate_token method
        mock_token_data = {"token": "mock_token", "expires_at": 1234567890}

        # Mock the ServerAPI and its delete_user method
        mock_response = MagicMock()
        mock_response.status = "success"
        mock_response.message = "User deleted successfully"
        mock_response.data = MagicMock()
        mock_response.data.deleted_contact_id = "contact_123"

        with patch.object(
            self.client, "generate_token", return_value=mock_token_data
        ) as mock_gen_token, patch(
            "contactsmanager.client.ServerAPI"
        ) as mock_server_api_class:

            mock_server_api = mock_server_api_class.return_value
            mock_server_api.delete_user.return_value = mock_response

            result = self.client.delete_user(uid)

            # Verify generate_token was called correctly
            mock_gen_token.assert_called_once_with(user_id=uid)

            # Verify ServerAPI was initialized with the token
            mock_server_api_class.assert_called_once_with("mock_token")

            # Verify delete_user was called on ServerAPI
            mock_server_api.delete_user.assert_called_once_with(uid=uid)

            # Verify the result
            self.assertEqual(result, mock_response)

    def test_delete_user_with_invalid_params(self):
        """Test delete_user with invalid parameters."""
        # Test with empty string
        with self.assertRaises(ValueError) as context:
            self.client.delete_user("")
        self.assertIn(
            "User ID is required and must be a string", str(context.exception)
        )

        # Test with None
        with self.assertRaises(ValueError) as context:
            self.client.delete_user(None)
        self.assertIn(
            "User ID is required and must be a string", str(context.exception)
        )

        # Test with wrong type
        with self.assertRaises(ValueError) as context:
            self.client.delete_user(123)
        self.assertIn(
            "User ID is required and must be a string", str(context.exception)
        )

    def test_delete_user_server_api_error(self):
        """Test delete_user when ServerAPI raises an error."""
        uid = "test_user_123"
        mock_token_data = {"token": "mock_token", "expires_at": 1234567890}

        with patch.object(
            self.client, "generate_token", return_value=mock_token_data
        ), patch("contactsmanager.client.ServerAPI") as mock_server_api_class:

            mock_server_api = mock_server_api_class.return_value
            mock_server_api.delete_user.side_effect = ServerAPIError("API Error", 404)

            with self.assertRaises(ServerAPIError):
                self.client.delete_user(uid)

    def test_set_webhook_secret(self):
        """Test setting webhook secret."""
        # Test with valid secret
        self.client.set_webhook_secret("valid_secret")
        self.assertEqual(self.client.webhook_secret, "valid_secret")

        # Test with invalid secrets
        with self.assertRaises(ValueError):
            self.client.set_webhook_secret("")

        with self.assertRaises(ValueError):
            self.client.set_webhook_secret(None)

        with self.assertRaises(ValueError):
            self.client.set_webhook_secret(123)

    def test_verify_webhook_signature_without_secret(self):
        """Test verify_webhook_signature without setting secret first."""
        with self.assertRaises(ValueError):
            self.client.verify_webhook_signature({}, "signature")

    def test_verify_webhook_signature_invalid_signature_format(self):
        """Test verify_webhook_signature with invalid signature format."""
        self.client.set_webhook_secret("webhook_secret")

        # Invalid format
        self.assertFalse(self.client.verify_webhook_signature({}, "invalid"))

        # Missing t parameter
        self.assertFalse(self.client.verify_webhook_signature({}, "v1=signature"))

        # Missing v1 parameter
        self.assertFalse(self.client.verify_webhook_signature({}, "t=123456789"))

    def test_verify_webhook_signature_expired_timestamp(self):
        """Test verify_webhook_signature with expired timestamp."""
        self.client.set_webhook_secret("webhook_secret")

        # Mock current time to 1000
        with patch("time.time", return_value=1000):
            # Timestamp is 15+ minutes old (900+ seconds)
            old_timestamp = 1000 - 901
            self.assertFalse(
                self.client.verify_webhook_signature(
                    {}, f"t={old_timestamp},v1=signature"
                )
            )

    def test_verify_webhook_signature_with_dict_payload(self):
        """Test verify_webhook_signature with dictionary payload."""
        secret = "webhook_secret"
        self.client.set_webhook_secret(secret)
        payload = {"id": "123", "event": "user.new", "data": {"user_id": "user123"}}
        timestamp = "1609459200"  # 2021-01-01 00:00:00 UTC

        # Create a valid signature
        payload_str = json.dumps(payload)
        signed_content = f"{timestamp}.{payload_str}"
        expected_signature = hmac.new(
            secret.encode("utf-8"), signed_content.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        signature_header = f"t={timestamp},v1={expected_signature}"

        # Mock time.time to return a fixed time close to the timestamp
        with patch("time.time", return_value=int(timestamp) + 10):
            # Mock the compare_digest to ensure it's called correctly
            with patch("hmac.compare_digest", return_value=True) as mock_compare:
                result = self.client.verify_webhook_signature(payload, signature_header)
                self.assertTrue(result)

                # Verify compare_digest was called with correct arguments
                mock_compare.assert_called_once_with(
                    expected_signature, expected_signature
                )

    def test_verify_webhook_signature_with_string_payload(self):
        """Test verify_webhook_signature with string payload."""
        secret = "webhook_secret"
        self.client.set_webhook_secret(secret)
        payload = '{"id":"123","event":"user.new"}'
        timestamp = "1609459200"

        # Create a valid signature
        signed_content = f"{timestamp}.{payload}"
        expected_signature = hmac.new(
            secret.encode("utf-8"), signed_content.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        signature_header = f"t={timestamp},v1={expected_signature}"

        with patch("time.time", return_value=int(timestamp) + 10):
            with patch("hmac.compare_digest", return_value=True):
                self.assertTrue(
                    self.client.verify_webhook_signature(payload, signature_header)
                )

    def test_verify_webhook_signature_with_bytes_payload(self):
        """Test verify_webhook_signature with bytes payload."""
        secret = "webhook_secret"
        self.client.set_webhook_secret(secret)
        payload = b'{"id":"123","event":"user.new"}'
        timestamp = "1609459200"

        # Create a valid signature
        signed_content = f"{timestamp}.{payload.decode('utf-8')}"
        expected_signature = hmac.new(
            secret.encode("utf-8"), signed_content.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        signature_header = f"t={timestamp},v1={expected_signature}"

        with patch("time.time", return_value=int(timestamp) + 10):
            with patch("hmac.compare_digest", return_value=True):
                self.assertTrue(
                    self.client.verify_webhook_signature(payload, signature_header)
                )

    def test_verify_webhook_signature_with_invalid_signature(self):
        """Test verify_webhook_signature with invalid signature."""
        secret = "webhook_secret"
        self.client.set_webhook_secret(secret)
        payload = {"id": "123", "event": "user.new"}
        timestamp = "1609459200"

        signature_header = f"t={timestamp},v1=invalid_signature"

        with patch("time.time", return_value=int(timestamp) + 10):
            with patch("hmac.compare_digest", return_value=False):
                self.assertFalse(
                    self.client.verify_webhook_signature(payload, signature_header)
                )

    def test_verify_webhook_signature_error_handling(self):
        """Test verify_webhook_signature error handling."""
        secret = "webhook_secret"
        self.client.set_webhook_secret(secret)

        # Test with malformed signature that causes an exception
        with patch("time.time", side_effect=Exception("Time error")):
            self.assertFalse(
                self.client.verify_webhook_signature({}, "t=123,v1=signature")
            )


if __name__ == "__main__":
    unittest.main()
