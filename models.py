"""
Data models and constants for Secure IoT Architecture.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time


class DeviceRole(str, Enum):
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    GATEWAY_ADMIN = "gateway_admin"
    DIAGNOSTIC = "diagnostic"
    GUEST = "guest"


class DeviceStatus(str, Enum):
    ACTIVE = "active"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    REVOKED = "revoked"


class NetworkZone(str, Enum):
    INTERNAL_IOT_LAN = "internal_iot_lan"
    SECURE_DMZ = "secure_dmz"
    EXTERNAL_WAN = "external_wan"


class ActionType(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    CONFIGURE = "configure"


class AccessDecisionType(str, Enum):
    ALLOW = "ALLOW"
    DENY_UNAUTHENTICATED = "DENY_UNAUTHENTICATED"
    DENY_UNAUTHORIZED_ROLE = "DENY_UNAUTHORIZED_ROLE"
    DENY_ATTRIBUTE_POLICY = "DENY_ATTRIBUTE_POLICY"
    DENY_REVOKED = "DENY_REVOKED"
    DENY_TOKEN_INVALID = "DENY_TOKEN_INVALID"


@dataclass
class DeviceAttributes:
    device_type: str
    firmware_version: float
    network_zone: NetworkZone
    location: str
    trust_score: int  # 0 to 100
    operational_hours: str = "24x7"  # e.g., "24x7" or "08:00-18:00"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_type": self.device_type,
            "firmware_version": self.firmware_version,
            "network_zone": self.network_zone.value,
            "location": self.location,
            "trust_score": self.trust_score,
            "operational_hours": self.operational_hours
        }


@dataclass
class IoTResource:
    resource_id: str
    name: str
    description: str
    allowed_roles: List[DeviceRole]
    allowed_actions: List[ActionType]
    min_firmware: float = 1.0
    allowed_zones: List[NetworkZone] = field(default_factory=lambda: [NetworkZone.INTERNAL_IOT_LAN])
    min_trust_score: int = 50
    is_critical: bool = False


@dataclass
class SecurityToken:
    token_id: str
    device_id: str
    role: DeviceRole
    attributes: Dict[str, Any]
    issued_at: float
    expires_at: float
    signature: str = ""

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at


@dataclass
class AccessResult:
    decision: AccessDecisionType
    allowed: bool
    reason: str
    resource_id: str
    device_id: str
    timestamp: float = field(default_factory=time.time)
