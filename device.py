"""
IoT Device Client Implementation.
Simulates legitimate, restricted, and adversarial edge devices.
"""
import hmac
import hashlib
import time
from typing import Dict, Any, Optional

from models import (
    DeviceRole,
    DeviceAttributes,
    SecurityToken,
    ActionType
)


class IoTDevice:
    """
    Simulated IoT device with cryptographic identity and security token management.
    """
    def __init__(
        self,
        device_id: str,
        secret_key: bytes,
        role: DeviceRole,
        attributes: DeviceAttributes
    ):
        self.device_id = device_id
        self.secret_key = secret_key
        self.role = role
        self.attributes = attributes
        
        self.active_token: Optional[SecurityToken] = None
        self.is_compromised: bool = False

    def create_auth_request(self) -> Dict[str, Any]:
        """Phase 1: Hello / Auth request payload."""
        return {
            "device_id": self.device_id,
            "timestamp": time.time()
        }

    def compute_challenge_response(self, nonce: str, timestamp: float) -> str:
        """
        Phase 2: Cryptographic signature computation over (device_id + nonce + timestamp).
        """
        msg = f"{self.device_id}:{nonce}:{timestamp}".encode("utf-8")
        signature = hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()
        return signature

    def store_token(self, token: SecurityToken):
        """Save issued capability token locally."""
        self.active_token = token

    def create_access_request(
        self,
        resource_id: str,
        action: ActionType,
        context_override: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Constructs a resource access request carrying the security token.
        """
        return {
            "device_id": self.device_id,
            "resource_id": resource_id,
            "action": action,
            "token": self.active_token,
            "context_override": context_override,
            "timestamp": time.time()
        }

    def mark_compromised(self):
        """Flag the device as compromised (e.g., malware or key exfiltration)."""
        self.is_compromised = True
        self.attributes.trust_score = 0
