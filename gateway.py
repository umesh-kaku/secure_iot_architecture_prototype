"""
IoT Security Gateway (Policy Enforcement Point - PEP).
Coordinates Authentication, Access Control, Revocation, and Resource execution.
Tracks end-to-end communication overhead and response latency.
"""
import time
import json
from typing import Dict, Any, Tuple, Optional

from models import (
    DeviceRole,
    DeviceAttributes,
    ActionType,
    AccessDecisionType,
    AccessResult,
    SecurityToken
)
from revocation import RevocationManager
from auth_server import AuthenticationServer
from access_control import PolicyDecisionPoint
from device import IoTDevice


class IoTGateway:
    """
    Secure IoT Gateway serving as Policy Enforcement Point (PEP)
    and central coordinator for all edge IoT interactions.
    """
    def __init__(self, token_ttl_seconds: int = 300):
        self.revocation_manager = RevocationManager()
        self.auth_server = AuthenticationServer(self.revocation_manager, token_ttl_seconds)
        self.pdp = PolicyDecisionPoint(self.auth_server, self.revocation_manager)
        
        # State of physical / simulated resources
        self._resource_state = {
            "res:telemetry:sensor_data": {"temperature": 23.5, "humidity": 45.0, "readings_count": 0},
            "res:actuator:water_pump": {"pump_active": False, "rpm": 0},
            "res:critical:power_grid_switch": {"grid_status": "ONLINE", "circuit_breaker": "CLOSED"},
            "res:system:firmware_update": {"installed_patch": "PATCH-2026.1"}
        }

    # --- Device Onboarding ---
    def register_device(
        self,
        device_id: str,
        secret_key: bytes,
        role: DeviceRole,
        attributes: DeviceAttributes
    ):
        """Register device identity in central authority."""
        self.auth_server.register_device(device_id, secret_key, role, attributes)

    # --- Handshake & Authentication (PEP Flow) ---
    def authenticate_device(
        self,
        device: IoTDevice,
        tamper_nonce: Optional[str] = None,
        tamper_sig: Optional[str] = None
    ) -> Tuple[bool, Optional[SecurityToken], str, Dict[str, int]]:
        """
        Executes complete Challenge-Response Handshake protocol between Device and Gateway.
        Returns: (success, token, status_message, overhead_bytes_dict)
        """
        overhead = {
            "phase1_request_bytes": 0,
            "phase2_challenge_bytes": 0,
            "phase3_response_bytes": 0,
            "phase4_token_issue_bytes": 0,
            "total_auth_bytes": 0
        }

        # Step 1: Device sends Auth Request (Phase 1)
        req_payload = device.create_auth_request()
        req_bytes = len(json.dumps(req_payload).encode("utf-8"))
        overhead["phase1_request_bytes"] = req_bytes

        # Step 2: Gateway issues Challenge Nonce (Phase 2)
        success, nonce, err = self.auth_server.generate_challenge(device.device_id)
        if not success:
            err_payload = {"status": "ERROR", "error": err}
            overhead["phase2_challenge_bytes"] = len(json.dumps(err_payload).encode("utf-8"))
            overhead["total_auth_bytes"] = overhead["phase1_request_bytes"] + overhead["phase2_challenge_bytes"]
            return False, None, err, overhead

        challenge_payload = {"nonce": nonce, "timestamp": time.time()}
        overhead["phase2_challenge_bytes"] = len(json.dumps(challenge_payload).encode("utf-8"))

        # Step 3: Device computes cryptographic signature (Phase 3)
        client_ts = time.time()
        effective_nonce = tamper_nonce if tamper_nonce is not None else nonce
        client_sig = device.compute_challenge_response(effective_nonce, client_ts)
        if tamper_sig is not None:
            client_sig = tamper_sig

        resp_payload = {
            "device_id": device.device_id,
            "nonce": effective_nonce,
            "timestamp": client_ts,
            "signature": client_sig
        }
        overhead["phase3_response_bytes"] = len(json.dumps(resp_payload).encode("utf-8"))

        # Step 4: Auth Server verifies signature and issues capability token (Phase 4)
        auth_success, token, msg = self.auth_server.verify_challenge_and_issue_token(
            device_id=device.device_id,
            nonce=effective_nonce,
            client_timestamp=client_ts,
            client_signature=client_sig,
            reported_attributes=device.attributes.to_dict()
        )

        if auth_success and token:
            token_payload = {
                "token_id": token.token_id,
                "device_id": token.device_id,
                "role": token.role.value,
                "expires_at": token.expires_at,
                "signature": token.signature
            }
            overhead["phase4_token_issue_bytes"] = len(json.dumps(token_payload).encode("utf-8"))
            device.store_token(token)
        else:
            fail_payload = {"status": "AUTH_FAILED", "message": msg}
            overhead["phase4_token_issue_bytes"] = len(json.dumps(fail_payload).encode("utf-8"))

        overhead["total_auth_bytes"] = (
            overhead["phase1_request_bytes"]
            + overhead["phase2_challenge_bytes"]
            + overhead["phase3_response_bytes"]
            + overhead["phase4_token_issue_bytes"]
        )

        return auth_success, token, msg, overhead

    # --- Resource Access Request (PEP Flow) ---
    def process_access_request(
        self,
        request_payload: Dict[str, Any]
    ) -> Tuple[AccessResult, Optional[Dict[str, Any]], Dict[str, int]]:
        """
        Policy Enforcement Point (PEP) handles resource request:
        1. PDP evaluates RBAC + ABAC + Revocation policies.
        2. If ALLOW, updates/reads critical resource and returns output.
        3. If DENY, blocks and logs security violation.
        """
        overhead = {
            "request_bytes": len(json.dumps({
                k: v for k, v in request_payload.items() if k != "token"
            }).encode("utf-8")),
            "token_bytes": 0,
            "response_bytes": 0,
            "total_access_bytes": 0
        }

        token: Optional[SecurityToken] = request_payload.get("token")
        if token:
            overhead["token_bytes"] = len(json.dumps({
                "token_id": token.token_id,
                "device_id": token.device_id,
                "role": token.role.value,
                "signature": token.signature
            }).encode("utf-8"))

        overhead["request_bytes"] += overhead["token_bytes"]

        resource_id = request_payload.get("resource_id")
        action = request_payload.get("action")
        context_override = request_payload.get("context_override")

        # Missing token defense
        if not token:
            res = AccessResult(
                decision=AccessDecisionType.DENY_UNAUTHENTICATED,
                allowed=False,
                reason="Authentication required: No security token presented.",
                resource_id=resource_id or "unknown",
                device_id=request_payload.get("device_id", "unknown")
            )
            overhead["response_bytes"] = len(json.dumps({"allowed": False, "reason": res.reason}).encode("utf-8"))
            overhead["total_access_bytes"] = overhead["request_bytes"] + overhead["response_bytes"]
            return res, None, overhead

        # Evaluate policies via PDP
        decision_result = self.pdp.evaluate_request(token, resource_id, action, context_override)

        resource_data = None
        if decision_result.allowed:
            # Execute operation on resource
            resource_data = self._execute_operation(resource_id, action, request_payload.get("params"))

        resp_payload = {
            "allowed": decision_result.allowed,
            "decision": decision_result.decision.value,
            "reason": decision_result.reason,
            "data": resource_data
        }
        overhead["response_bytes"] = len(json.dumps(resp_payload).encode("utf-8"))
        overhead["total_access_bytes"] = overhead["request_bytes"] + overhead["response_bytes"]

        return decision_result, resource_data, overhead

    def _execute_operation(self, resource_id: str, action: ActionType, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulate physical operation on resource upon authorized access."""
        current = self._resource_state.get(resource_id, {})
        if resource_id == "res:telemetry:sensor_data":
            if action == ActionType.WRITE and params:
                current["temperature"] = params.get("temp", current["temperature"])
                current["humidity"] = params.get("humidity", current["humidity"])
                current["readings_count"] += 1
            return dict(current)
        elif resource_id == "res:actuator:water_pump":
            if action == ActionType.EXECUTE and params:
                current["pump_active"] = params.get("pump_active", True)
                current["rpm"] = params.get("rpm", 1500)
            return dict(current)
        elif resource_id == "res:critical:power_grid_switch":
            if action == ActionType.EXECUTE and params:
                current["circuit_breaker"] = params.get("switch_state", "TRIPPED")
            return dict(current)
        elif resource_id == "res:system:firmware_update":
            if action == ActionType.EXECUTE and params:
                current["installed_patch"] = params.get("patch", "PATCH-NEW")
            return dict(current)
        return dict(current)

    # --- Revocation API ---
    def revoke_device(self, device_id: str, reason: str = "Compromised"):
        """Instant kill-switch to revoke a device and drop its tokens."""
        return self.revocation_manager.revoke_device(device_id, reason)

    def revoke_token(self, token_id: str, device_id: str = "unknown", reason: str = "Suspicious activity"):
        return self.revocation_manager.revoke_token(token_id, device_id, reason)
