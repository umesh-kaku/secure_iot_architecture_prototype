"""
Access Control Module for Secure IoT Architecture.
Implements Policy Decision Point (PDP) combining:
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Revocation and Integrity verification
"""
from typing import Dict, Any, Tuple
import time

from models import (
    DeviceRole,
    NetworkZone,
    ActionType,
    IoTResource,
    SecurityToken,
    AccessDecisionType,
    AccessResult
)
from revocation import RevocationManager
from auth_server import AuthenticationServer


class PolicyDecisionPoint:
    """
    Evaluates access requests against both RBAC and ABAC security policies.
    """
    def __init__(self, auth_server: AuthenticationServer, revocation_manager: RevocationManager):
        self.auth_server = auth_server
        self.revocation_manager = revocation_manager
        
        # In-memory Resource Catalog
        self._resources: Dict[str, IoTResource] = {}
        self._init_default_resources()

    def _init_default_resources(self):
        """Populate realistic IoT resources with varying criticality."""
        # 1. Telemetry Data Store (Low criticality: Sensors write, Admins read)
        self.add_resource(
            IoTResource(
                resource_id="res:telemetry:sensor_data",
                name="Environmental Telemetry Store",
                description="Time-series temperature and humidity buffer",
                allowed_roles=[DeviceRole.SENSOR, DeviceRole.GATEWAY_ADMIN],
                allowed_actions=[ActionType.READ, ActionType.WRITE],
                min_firmware=1.0,
                allowed_zones=[NetworkZone.INTERNAL_IOT_LAN, NetworkZone.SECURE_DMZ],
                min_trust_score=40,
                is_critical=False
            )
        )

        # 2. Water Pump Actuator (Medium criticality: Actuators execute control signals)
        self.add_resource(
            IoTResource(
                resource_id="res:actuator:water_pump",
                name="Industrial Water Pump Actuator",
                description="Physical valve and motor actuation controls",
                allowed_roles=[DeviceRole.ACTUATOR, DeviceRole.GATEWAY_ADMIN],
                allowed_actions=[ActionType.READ, ActionType.EXECUTE],
                min_firmware=1.5,
                allowed_zones=[NetworkZone.INTERNAL_IOT_LAN],
                min_trust_score=70,
                is_critical=False
            )
        )

        # 3. Power Grid Relay Switch (High criticality: strictly Admin only, internal network only)
        self.add_resource(
            IoTResource(
                resource_id="res:critical:power_grid_switch",
                name="Substation Power Grid Main Relay",
                description="High-voltage power distribution switch",
                allowed_roles=[DeviceRole.GATEWAY_ADMIN],
                allowed_actions=[ActionType.EXECUTE, ActionType.CONFIGURE],
                min_firmware=2.0,
                allowed_zones=[NetworkZone.INTERNAL_IOT_LAN],
                min_trust_score=85,
                is_critical=True
            )
        )

        # 4. Firmware Update Service (High criticality: System updates)
        self.add_resource(
            IoTResource(
                resource_id="res:system:firmware_update",
                name="Over-The-Air Firmware Management",
                description="Flashing new software and security patches",
                allowed_roles=[DeviceRole.GATEWAY_ADMIN, DeviceRole.DIAGNOSTIC],
                allowed_actions=[ActionType.WRITE, ActionType.EXECUTE],
                min_firmware=2.0,
                allowed_zones=[NetworkZone.INTERNAL_IOT_LAN],
                min_trust_score=80,
                is_critical=True
            )
        )

    def add_resource(self, resource: IoTResource):
        self._resources[resource.resource_id] = resource

    def get_resource(self, resource_id: str) -> IoTResource:
        return self._resources.get(resource_id)

    def evaluate_request(
        self,
        token: SecurityToken,
        resource_id: str,
        action: ActionType,
        context_override: Dict[str, Any] = None
    ) -> AccessResult:
        """
        Unified PEP/PDP Access Decision Pipeline:
        1. Token validity & Revocation check
        2. Resource existence check
        3. RBAC Policy Evaluation
        4. ABAC Policy Evaluation
        """
        device_id = token.device_id

        # --- Step 1: Revocation Check ---
        if self.revocation_manager.is_device_revoked(device_id):
            return AccessResult(
                decision=AccessDecisionType.DENY_REVOKED,
                allowed=False,
                reason=f"Device '{device_id}' is permanently revoked / blacklisted.",
                resource_id=resource_id,
                device_id=device_id
            )

        if self.revocation_manager.is_token_revoked(token.token_id):
            return AccessResult(
                decision=AccessDecisionType.DENY_REVOKED,
                allowed=False,
                reason=f"Access token '{token.token_id}' has been revoked.",
                resource_id=resource_id,
                device_id=device_id
            )

        # --- Step 2: Cryptographic Token Integrity & Expiry ---
        is_token_valid, err_msg = self.auth_server.verify_token(token)
        if not is_token_valid:
            return AccessResult(
                decision=AccessDecisionType.DENY_TOKEN_INVALID,
                allowed=False,
                reason=f"Token verification failed: {err_msg}",
                resource_id=resource_id,
                device_id=device_id
            )

        # --- Step 3: Resource Verification ---
        resource = self._resources.get(resource_id)
        if not resource:
            return AccessResult(
                decision=AccessDecisionType.DENY_ATTRIBUTE_POLICY,
                allowed=False,
                reason=f"Target resource '{resource_id}' does not exist.",
                resource_id=resource_id,
                device_id=device_id
            )

        # --- Step 4: RBAC Policy Evaluation ---
        # Rule 4.1: Role must be in resource's allowed_roles
        if token.role not in resource.allowed_roles:
            return AccessResult(
                decision=AccessDecisionType.DENY_UNAUTHORIZED_ROLE,
                allowed=False,
                reason=(
                    f"RBAC Violation: Role '{token.role.value}' is not authorized "
                    f"for resource '{resource.name}'. Allowed: {[r.value for r in resource.allowed_roles]}"
                ),
                resource_id=resource_id,
                device_id=device_id
            )

        # Rule 4.2: Action must be permitted for resource
        if action not in resource.allowed_actions:
            return AccessResult(
                decision=AccessDecisionType.DENY_UNAUTHORIZED_ROLE,
                allowed=False,
                reason=(
                    f"RBAC Violation: Action '{action.value}' is not permitted on '{resource.name}'. "
                    f"Allowed: {[a.value for a in resource.allowed_actions]}"
                ),
                resource_id=resource_id,
                device_id=device_id
            )

        # --- Step 5: ABAC Policy Evaluation ---
        # Consolidate effective attributes (token claims + dynamic context)
        attrs = dict(token.attributes)
        if context_override:
            attrs.update(context_override)

        # ABAC Rule 5.1: Minimum Firmware Version Check
        device_fw = float(attrs.get("firmware_version", 0.0))
        if device_fw < resource.min_firmware:
            return AccessResult(
                decision=AccessDecisionType.DENY_ATTRIBUTE_POLICY,
                allowed=False,
                reason=(
                    f"ABAC Violation: Device firmware v{device_fw:.1f} is below minimum "
                    f"required v{resource.min_firmware:.1f} for '{resource.name}'."
                ),
                resource_id=resource_id,
                device_id=device_id
            )

        # ABAC Rule 5.2: Network Zone Constraint
        device_zone_val = attrs.get("network_zone")
        device_zone = NetworkZone(device_zone_val) if device_zone_val else NetworkZone.EXTERNAL_WAN
        if device_zone not in resource.allowed_zones:
            return AccessResult(
                decision=AccessDecisionType.DENY_ATTRIBUTE_POLICY,
                allowed=False,
                reason=(
                    f"ABAC Violation: Access from network zone '{device_zone.value}' denied. "
                    f"Allowed zones: {[z.value for z in resource.allowed_zones]}"
                ),
                resource_id=resource_id,
                device_id=device_id
            )

        # ABAC Rule 5.3: Minimum Trust Score
        device_trust = int(attrs.get("trust_score", 0))
        if device_trust < resource.min_trust_score:
            return AccessResult(
                decision=AccessDecisionType.DENY_ATTRIBUTE_POLICY,
                allowed=False,
                reason=(
                    f"ABAC Violation: Device trust score ({device_trust}) is below required "
                    f"threshold ({resource.min_trust_score}) for '{resource.name}'."
                ),
                resource_id=resource_id,
                device_id=device_id
            )

        # ABAC Rule 5.4: Critical Resource Strictness
        if resource.is_critical:
            # Enforce that critical access cannot originate from diagnostic or guest roles
            if token.role in [DeviceRole.GUEST, DeviceRole.DIAGNOSTIC]:
                return AccessResult(
                    decision=AccessDecisionType.DENY_ATTRIBUTE_POLICY,
                    allowed=False,
                    reason=f"ABAC Violation: Critical resource '{resource.name}' prohibits diagnostic/guest access.",
                    resource_id=resource_id,
                    device_id=device_id
                )

        # All RBAC and ABAC checks passed
        return AccessResult(
            decision=AccessDecisionType.ALLOW,
            allowed=True,
            reason=f"Access Granted: Role and ABAC attributes satisfy security policies for '{resource.name}'.",
            resource_id=resource_id,
            device_id=device_id
        )
