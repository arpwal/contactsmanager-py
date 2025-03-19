import unittest
import time
import jwt
from unittest.mock import patch
from contactsmanager import ContactsManagerClient


class TestContactsManagerClient(unittest.TestCase):
    def setUp(self):
        self.api_key = "test_api_key"
        self.api_secret = "test_api_secret"
        self.org_id = "test_org_id"
        self.client = ContactsManagerClient(
            api_key=self.api_key,
            api_secret=self.api_secret,
            org_id=self.org_id
        )
    
    def test_init_with_valid_params(self):
        """Test that the client initializes correctly with valid parameters."""
        self.assertEqual(self.client.api_key, self.api_key)
        self.assertEqual(self.client.api_secret, self.api_secret)
        self.assertEqual(self.client.org_id, self.org_id)
    
    def test_init_with_invalid_params(self):
        """Test that the client raises ValueError with invalid parameters."""
        with self.assertRaises(ValueError):
            ContactsManagerClient(api_key="", api_secret=self.api_secret, org_id=self.org_id)
        
        with self.assertRaises(ValueError):
            ContactsManagerClient(api_key=self.api_key, api_secret="", org_id=self.org_id)
        
        with self.assertRaises(ValueError):
            ContactsManagerClient(api_key=self.api_key, api_secret=self.api_secret, org_id="")
        
        with self.assertRaises(ValueError):
            ContactsManagerClient(api_key=123, api_secret=self.api_secret, org_id=self.org_id)
    
    def test_generate_token_with_valid_params(self):
        """Test that generate_token works with valid parameters."""
        user_id = "test_user_id"
        device_info = {"device": "web", "browser": "chrome"}
        
        # Mock UUID and time for deterministic tests
        with patch('uuid.uuid4', return_value="mock-uuid"), \
             patch('time.time', return_value=1000000):
            
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
                options={"verify_exp": False}  # Skip expiration verification
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
        
        with patch('time.time', return_value=1000000):
            token_data = self.client.generate_token(user_id, expiration_seconds=expiration)
            self.assertEqual(token_data["expires_at"], 1000000 + expiration)
    
    def test_generate_token_with_invalid_params(self):
        """Test that generate_token raises ValueError with invalid parameters."""
        with self.assertRaises(ValueError):
            self.client.generate_token(user_id="")
        
        with self.assertRaises(ValueError):
            self.client.generate_token(user_id=123)
        
        with self.assertRaises(ValueError):
            self.client.generate_token(user_id="test_user", device_info="not_a_dict")


if __name__ == "__main__":
    unittest.main() 