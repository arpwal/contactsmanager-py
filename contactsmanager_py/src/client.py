import jwt
import time
import uuid
from typing import Dict, Optional, Union

class ContactsManagerClient:
    def __init__(self, api_key: str, api_secret: str, org_id: str):
        """
        Initialize the ContactsManager SDK client.
        
        Args:
            api_key (str): Your organization's API key
            api_secret (str): Your organization's API secret
            org_id (str): Your organization's ID
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.org_id = org_id

    def generate_token(self, user_id: str, device_info: Optional[Dict] = None) -> Dict[str, Union[str, int]]:
        """
        Generate a client token for a specific user.
        
        Args:
            user_id (str): The ID of the user to generate the token for
            device_info (dict, optional): Additional device metadata
            
        Returns:
            dict: A dictionary containing the token and its expiration timestamp
        """
        if not user_id:
            raise ValueError("user_id is required")
            
        now = int(time.time())
        
        payload = {
            "iss": "contactsmanager",
            "org_id": self.org_id,
            "api_key": self.api_key,
            "user_id": user_id,
            "device_info": device_info or {},
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + (24 * 60 * 60)  # 24 hours expiry
        }
        
        token = jwt.encode(
            payload,
            self.api_secret,
            algorithm="HS256"
        )
        
        return {
            "token": token,
            "expires_at": payload["exp"]
        } 