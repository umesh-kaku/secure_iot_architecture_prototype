"""
Authentication Authority / Server for IoT Architecture.
Implements Cryptographic Identity Registration, Challenge-Response Handshake,
Replay Attack Protection, and Capability-based Token Issuance.
"""
import hmac
import hashlib
import secrets
import json
import time
from typing import Dict, Optional, Tuple, Any

from models import (
    DeviceRole,
    DeviceAttributes,
    SecurityToken,
    AccessDecisionType
)
from revocation import RevocationManager


class AuthenticationServer:
    """
    Central Authentication Server responsible for verifying device identities
    and generating tamper-proof security tokens.
    """
    def __init__(self, revocation_manager: RevocationManager, token_ttl_seconds: int = 300):
        self.revocation_manager = revocation_manager
        self.token_ttl_seconds = token_ttl_seconds
        
        # Server's internal secret key used for signing security tokens
        self._server_token_key = secrets.token_bytes(32)
        
        # Device Registry: device_id -> {secret_key: bytes, role: DeviceRole, attributes: DeviceAttributes}
        self._device_registry: Dict[str, Dict[str, Any]] = {}
        
        # Active challenge nonces: nonce -> {"device_id": str, "created_at": float, "used": bool}
        self._active_nonces: Dict[str, Dict[str, Any]] = {}
        self.nonce_ttl = 30.0  # seconds

    def register_device(
        self,
        device_id: str,
        secret_key: bytes,
        role: DeviceRole,
        attributes: DeviceAttributes
    ) -> bool:
        """Register a valid device identity in the secure IoT directory."""
        self._device_registry[device_id] = {
            "secret_key": secret_key,
            "role": role,
            "attributes": attributes
        }
        return True

    def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        return self._device_registry.get(device_id)

    # --- Phase 1: Handshake Challenge Request ---
    def generate_challenge(self, device_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Device requests an authentication challenge.
        Returns: (success, nonce_or_error, error_message)
        """
        # 1. Check if device is revoked
        if self.revocation_manager.is_device_revoked(device_id):
            return False, None, "DEVICE_REVOKED"

        # 2. Check if device is in registry
        if device_id not in self._device_registry:
            return False, None, "DEVICE_UNREGISTERED"

        # 3. Generate cryptographically strong random nonce
        nonce = secrets.token_hex(16)
        self._active_nonces[nonce] = {
            "device_id": device_id,
            "created_at": time.time(),
            "used": False
        }
        return True, nonce, None

    # --- Phase 2: Challenge Verification & Token Issuance ---
    def verify_challenge_and_issue_token(
        self,
        device_id: str,
        nonce: str,
        client_timestamp: float,
        client_signature: str,
        reported_attributes: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[SecurityToken], str]:
        """
        Verifies the cryptographic response from the IoT device.
        If valid, issues a signed SecurityToken.
        """
        # 1. Revocation check
        if self.revocation_manager.is_device_revoked(device_id):
            return False, None, "DEVICE_REVOKED"

        # 2. Registry check
        reg_info = self._device_registry.get(device_id)
        if not reg_info:
            return False, None, "DEVICE_UNREGISTERED"

        # 3. Nonce validation (Replay attack defense)
        nonce_record = self._active_nonces.get(nonce)
        if not nonce_record:
            return False, None, "INVALID_NONCE"

        if nonce_record["used"]:
            return False, None, "NONCE_REPLAY_DETECTED"

        if nonce_record["device_id"] != device_id:
            return False, None, "NONCE_DEVICE_MISMATCH"

        now = time.time()
        if now - nonce_record["created_at"] > self.nonce_ttl:
            return False, None, "NONCE_EXPIRED"

        # Mark nonce as consumed immediately
        nonce_record["used"] = True

        # 4. Cryptographic Signature Verification
        secret_key = reg_info["secret_key"]
        expected_msg = f"{device_id}:{nonce}:{client_timestamp}".encode("utf-8")
        expected_sig = hmac.new(secret_key, expected_msg, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_sig, client_signature):
            return False, None, "CRYPTOGRAPHIC_SIGNATURE_MISMATCH"

        # 5. Issue Capability / Security Token
        # Use registered attributes or updated verified attributes
        device_attrs = reg_info["attributes"].to_dict()
        if reported_attributes:
            device_attrs.update(reported_attributes)

        token_id = secrets.token_hex(12)
        issued_at = now
        expires_at = now + self.token_ttl_seconds

        token = SecurityToken(
            token_id=token_id,
            device_id=device_id,
            role=reg_info["role"],
            attributes=device_attrs,
            issued_at=issued_at,
            expires_at=expires_at
        )

        # Sign token payload using Server Key
        token.signature = self._sign_token(token)
        return True, token, "AUTHENTICATION_SUCCESS"

    def _canonical_token_string(self, token: SecurityToken) -> str:
        attrs_json = json.dumps(token.attributes, sort_keys=True)
        return f"{token.token_id}|{token.device_id}|{token.role.value}|{token.issued_at:.3f}|{token.expires_at:.3f}|{attrs_json}"

    def _sign_token(self, token: SecurityToken) -> str:
        payload = self._canonical_token_string(token).encode("utf-8")
        return hmac.new(self._server_token_key, payload, hashlib.sha256).hexdigest()

    def verify_token(self, token: SecurityToken) -> Tuple[bool, str]:
        """
        Validates token signature, expiration, and revocation status.
        """
        # 1. Device or token revoked?
        if self.revocation_manager.is_device_revoked(token.device_id):
            return False, "DEVICE_IS_REVOKED"

        if self.revocation_manager.is_token_revoked(token.token_id):
            return False, "TOKEN_IS_REVOKED"

        # 2. Expiration check
        if token.is_expired():
            return False, "TOKEN_EXPIRED"

        # 3. Cryptographic Signature check (Tamper-evidence)
        expected_sig = self._sign_token(token)
        if not hmac.compare_digest(expected_sig, token.signature):
            return False, "TOKEN_SIGNATURE_TAMPERED"

        return True, "TOKEN_VALID"
