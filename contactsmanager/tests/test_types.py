import unittest
from contactsmanager.types import (
    UserInfo,
    DeviceInfo,
    TokenData,
    CMUser,
    CreateUserData,
    CreateUserResponse,
    DeleteUserData,
    DeleteUserResponse,
)


class TestUserInfo(unittest.TestCase):
    """Test cases for UserInfo dataclass."""

    def test_valid_user_info_with_email(self):
        """Test creating UserInfo with valid data including email."""
        user_info = UserInfo(
            user_id="test_user_123", full_name="Test User", email="test@example.com"
        )
        self.assertEqual(user_info.user_id, "test_user_123")
        self.assertEqual(user_info.full_name, "Test User")
        self.assertEqual(user_info.email, "test@example.com")
        self.assertIsNone(user_info.phone)

    def test_valid_user_info_with_phone(self):
        """Test creating UserInfo with valid data including phone."""
        user_info = UserInfo(
            user_id="test_user_123", full_name="Test User", phone="+1234567890"
        )
        self.assertEqual(user_info.user_id, "test_user_123")
        self.assertEqual(user_info.full_name, "Test User")
        self.assertEqual(user_info.phone, "+1234567890")
        self.assertIsNone(user_info.email)

    def test_valid_user_info_with_both_email_and_phone(self):
        """Test creating UserInfo with both email and phone."""
        user_info = UserInfo(
            user_id="test_user_123",
            full_name="Test User",
            email="test@example.com",
            phone="+1234567890",
            avatar_url="https://example.com/avatar.jpg",
            metadata={"role": "admin"},
        )
        self.assertEqual(user_info.user_id, "test_user_123")
        self.assertEqual(user_info.full_name, "Test User")
        self.assertEqual(user_info.email, "test@example.com")
        self.assertEqual(user_info.phone, "+1234567890")
        self.assertEqual(user_info.avatar_url, "https://example.com/avatar.jpg")
        self.assertEqual(user_info.metadata, {"role": "admin"})

    def test_invalid_user_info_empty_user_id(self):
        """Test UserInfo validation with empty user_id."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="", full_name="Test User", email="test@example.com")
        self.assertIn(
            "user_id is required and must be a non-empty string", str(context.exception)
        )

    def test_invalid_user_info_none_user_id(self):
        """Test UserInfo validation with None user_id."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id=None, full_name="Test User", email="test@example.com")
        self.assertIn(
            "user_id is required and must be a non-empty string", str(context.exception)
        )

    def test_invalid_user_info_non_string_user_id(self):
        """Test UserInfo validation with non-string user_id."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id=123, full_name="Test User", email="test@example.com")
        self.assertIn(
            "user_id is required and must be a non-empty string", str(context.exception)
        )

    def test_invalid_user_info_empty_full_name(self):
        """Test UserInfo validation with empty full_name."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="test_user", full_name="", email="test@example.com")
        self.assertIn(
            "full_name is required and must be a non-empty string",
            str(context.exception),
        )

    def test_invalid_user_info_none_full_name(self):
        """Test UserInfo validation with None full_name."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="test_user", full_name=None, email="test@example.com")
        self.assertIn(
            "full_name is required and must be a non-empty string",
            str(context.exception),
        )

    def test_invalid_user_info_no_email_or_phone(self):
        """Test UserInfo validation when neither email nor phone is provided."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="test_user", full_name="Test User")
        self.assertIn(
            "At least one of email or phone must be provided", str(context.exception)
        )

    def test_invalid_user_info_non_string_email(self):
        """Test UserInfo validation with non-string email."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="test_user", full_name="Test User", email=123)
        self.assertIn("email must be a string", str(context.exception))

    def test_invalid_user_info_non_string_phone(self):
        """Test UserInfo validation with non-string phone."""
        with self.assertRaises(ValueError) as context:
            UserInfo(user_id="test_user", full_name="Test User", phone=123)
        self.assertIn("phone must be a string", str(context.exception))

    def test_user_info_to_dict(self):
        """Test UserInfo to_dict conversion."""
        user_info = UserInfo(
            user_id="test_user_123",
            full_name="Test User",
            email="test@example.com",
            phone="+1234567890",
            avatar_url="https://example.com/avatar.jpg",
            metadata={"role": "admin"},
        )

        expected_dict = {
            "userId": "test_user_123",
            "fullName": "Test User",
            "email": "test@example.com",
            "phone": "+1234567890",
            "avatarUrl": "https://example.com/avatar.jpg",
            "metadata": {"role": "admin"},
        }

        self.assertEqual(user_info.to_dict(), expected_dict)

    def test_user_info_to_dict_minimal(self):
        """Test UserInfo to_dict conversion with minimal data."""
        user_info = UserInfo(
            user_id="test_user_123", full_name="Test User", email="test@example.com"
        )

        expected_dict = {
            "userId": "test_user_123",
            "fullName": "Test User",
            "email": "test@example.com",
        }

        self.assertEqual(user_info.to_dict(), expected_dict)


class TestDeviceInfo(unittest.TestCase):
    """Test cases for DeviceInfo dataclass."""

    def test_device_info_creation(self):
        """Test creating DeviceInfo with various parameters."""
        device_info = DeviceInfo(
            device_type="mobile",
            os="iOS",
            app_version="1.0.0",
            locale="en_US",
            timezone="America/New_York",
            additional_info={"custom_field": "value"},
        )

        self.assertEqual(device_info.device_type, "mobile")
        self.assertEqual(device_info.os, "iOS")
        self.assertEqual(device_info.app_version, "1.0.0")
        self.assertEqual(device_info.locale, "en_US")
        self.assertEqual(device_info.timezone, "America/New_York")
        self.assertEqual(device_info.additional_info, {"custom_field": "value"})

    def test_device_info_to_dict(self):
        """Test DeviceInfo to_dict conversion."""
        device_info = DeviceInfo(
            device_type="mobile",
            os="iOS",
            app_version="1.0.0",
            locale="en_US",
            timezone="America/New_York",
            additional_info={"custom_field": "value"},
        )

        expected_dict = {
            "deviceType": "mobile",
            "os": "iOS",
            "appVersion": "1.0.0",
            "locale": "en_US",
            "timezone": "America/New_York",
            "custom_field": "value",
        }

        self.assertEqual(device_info.to_dict(), expected_dict)

    def test_device_info_to_dict_minimal(self):
        """Test DeviceInfo to_dict conversion with minimal data."""
        device_info = DeviceInfo()
        self.assertEqual(device_info.to_dict(), {})

    def test_device_info_to_dict_partial(self):
        """Test DeviceInfo to_dict conversion with partial data."""
        device_info = DeviceInfo(device_type="web", app_version="2.0.0")

        expected_dict = {"deviceType": "web", "appVersion": "2.0.0"}

        self.assertEqual(device_info.to_dict(), expected_dict)


class TestResponseTypes(unittest.TestCase):
    """Test cases for response type dataclasses."""

    def test_create_user_response_from_dict(self):
        """Test CreateUserResponse.from_dict method."""
        response_data = {
            "status": "success",
            "data": {
                "token": {"token": "jwt_token_here", "expires_at": 1234567890},
                "user": {
                    "id": "user_123",
                    "organization_id": "org_456",
                    "organization_user_id": "ext_user_789",
                    "email": "test@example.com",
                    "phone": "+1234567890",
                    "full_name": "Test User",
                    "avatar_url": "https://example.com/avatar.jpg",
                    "contact_metadata": {"role": "admin"},
                    "is_active": True,
                    "created_at": "2023-01-01T00:00:00Z",
                    "updated_at": "2023-01-01T00:00:00Z",
                },
                "created": True,
            },
        }

        response = CreateUserResponse.from_dict(response_data)

        self.assertEqual(response.status, "success")
        self.assertEqual(response.data.token.token, "jwt_token_here")
        self.assertEqual(response.data.token.expires_at, 1234567890)
        self.assertEqual(response.data.user.id, "user_123")
        self.assertEqual(response.data.user.organization_id, "org_456")
        self.assertEqual(response.data.user.organization_user_id, "ext_user_789")
        self.assertEqual(response.data.user.email, "test@example.com")
        self.assertEqual(response.data.user.phone, "+1234567890")
        self.assertEqual(response.data.user.full_name, "Test User")
        self.assertEqual(
            response.data.user.avatar_url, "https://example.com/avatar.jpg"
        )
        self.assertEqual(response.data.user.contact_metadata, {"role": "admin"})
        self.assertTrue(response.data.user.is_active)
        self.assertEqual(response.data.user.created_at, "2023-01-01T00:00:00Z")
        self.assertEqual(response.data.user.updated_at, "2023-01-01T00:00:00Z")
        self.assertTrue(response.data.created)

    def test_delete_user_response_from_dict(self):
        """Test DeleteUserResponse.from_dict method."""
        response_data = {
            "status": "success",
            "message": "User deleted successfully",
            "data": {"deleted_contact_id": "contact_123"},
        }

        response = DeleteUserResponse.from_dict(response_data)

        self.assertEqual(response.status, "success")
        self.assertEqual(response.message, "User deleted successfully")
        self.assertEqual(response.data.deleted_contact_id, "contact_123")

    def test_cm_user_creation(self):
        """Test CMUser dataclass creation."""
        cm_user = CMUser(
            id="user_123",
            organization_id="org_456",
            organization_user_id="ext_user_789",
            email="test@example.com",
            phone="+1234567890",
            full_name="Test User",
            avatar_url="https://example.com/avatar.jpg",
            contact_metadata={"role": "admin"},
            is_active=True,
            created_at="2023-01-01T00:00:00Z",
            updated_at="2023-01-01T00:00:00Z",
        )

        self.assertEqual(cm_user.id, "user_123")
        self.assertEqual(cm_user.organization_id, "org_456")
        self.assertEqual(cm_user.organization_user_id, "ext_user_789")
        self.assertEqual(cm_user.email, "test@example.com")
        self.assertEqual(cm_user.phone, "+1234567890")
        self.assertEqual(cm_user.full_name, "Test User")
        self.assertEqual(cm_user.avatar_url, "https://example.com/avatar.jpg")
        self.assertEqual(cm_user.contact_metadata, {"role": "admin"})
        self.assertTrue(cm_user.is_active)
        self.assertEqual(cm_user.created_at, "2023-01-01T00:00:00Z")
        self.assertEqual(cm_user.updated_at, "2023-01-01T00:00:00Z")

    def test_token_data_creation(self):
        """Test TokenData dataclass creation."""
        token_data = TokenData(token="jwt_token_here", expires_at=1234567890)

        self.assertEqual(token_data.token, "jwt_token_here")
        self.assertEqual(token_data.expires_at, 1234567890)


if __name__ == "__main__":
    unittest.main()
