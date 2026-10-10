"""
Access Revocation Module for IoT Architecture.
Maintains Device Revocation List (DRL) and Token Revocation List (TRL).
"""
import time
from typing import Dict, Set, Optional


class RevocationManager:
    """
    Centralized Revocation Manager for handling compromised devices
    and revoked security tokens in real time.
    """
    def __init__(self):
        # device_id -> {"timestamp": float, "reason": str}
        self._revoked_devices: Dict[str, Dict[str, any]] = {}
        # token_id -> {"timestamp": float, "reason": str, "device_id": str}
        self._revoked_tokens: Dict[str, Dict[str, any]] = {}
        # Fast lookup sets
        self._revoked_device_ids: Set[str] = set()
        self._revoked_token_ids: Set[str] = set()

    def revoke_device(self, device_id: str, reason: str = "Compromise detected") -> Dict[str, any]:
        """
        Immediately blacklist a device and mark it as revoked.
        Any subsequent authentication or resource access will be denied.
        """
        entry = {
            "device_id": device_id,
            "timestamp": time.time(),
            "reason": reason
        }
        self._revoked_devices[device_id] = entry
        self._revoked_device_ids.add(device_id)
        return entry

    def revoke_token(self, token_id: str, device_id: str = "unknown", reason: str = "Token invalidated") -> Dict[str, any]:
        """
        Blacklist a specific access token before its natural expiry.
        """
        entry = {
            "token_id": token_id,
            "device_id": device_id,
            "timestamp": time.time(),
            "reason": reason
        }
        self._revoked_tokens[token_id] = entry
        self._revoked_token_ids.add(token_id)
        return entry

    def is_device_revoked(self, device_id: str) -> bool:
        """Check if a device identity is in the revocation blacklist."""
        return device_id in self._revoked_device_ids

    def is_token_revoked(self, token_id: str) -> bool:
        """Check if an access token is in the revocation blacklist."""
        return token_id in self._revoked_token_ids

    def get_device_revocation_details(self, device_id: str) -> Optional[Dict[str, any]]:
        return self._revoked_devices.get(device_id)

    def get_token_revocation_details(self, token_id: str) -> Optional[Dict[str, any]]:
        return self._revoked_tokens.get(token_id)

    def get_stats(self) -> Dict[str, int]:
        return {
            "total_revoked_devices": len(self._revoked_device_ids),
            "total_revoked_tokens": len(self._revoked_token_ids)
        }
