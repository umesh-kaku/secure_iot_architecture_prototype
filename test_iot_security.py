"""
Unit and Integration Test Suite for Secure IoT Architecture.
Tests:
- Identity Registration & Authentication Handshake
- Nonce Replay & Cryptographic Tampering Defenses
- RBAC & ABAC Policy Enforcement
- Instant Device & Token Revocation
- Quantitative Evaluator Integration
"""
import unittest
import time
import secrets

from models import (
    DeviceRole,
    DeviceAttributes,
    NetworkZone,
    ActionType,
    AccessDecisionType,
    SecurityToken
)
from gateway import IoTGateway
from device import IoTDevice
from evaluator import SecurityEvaluator


class TestSecureIoTArchitecture(unittest.TestCase):
    def setUp(self):
        self.gateway = IoTGateway(token_ttl_seconds=300)

        # Provision Test Sensor
        self.sensor_key = secrets.token_bytes(32)
        self.sensor_attrs = DeviceAttributes(
            device_type="temp_sensor",
            firmware_version=2.0,
            network_zone=NetworkZone.INTERNAL_IOT_LAN,
            location="Room-101",
            trust_score=90
        )
        self.sensor = IoTDevice("sensor-01", self.sensor_key, DeviceRole.SENSOR, self.sensor_attrs)
        self.gateway.register_device(self.sensor.device_id, self.sensor_key, self.sensor.role, self.sensor_attrs)

        # Provision Test Admin
        self.admin_key = secrets.token_bytes(32)
        self.admin_attrs = DeviceAttributes(
            device_type="admin_node",
            firmware_version=2.5,
            network_zone=NetworkZone.INTERNAL_IOT_LAN,
            location="Control-Room",
            trust_score=98
        )
        self.admin = IoTDevice("admin-01", self.admin_key, DeviceRole.GATEWAY_ADMIN, self.admin_attrs)
        self.gateway.register_device(self.admin.device_id, self.admin_key, self.admin.role, self.admin_attrs)

    def test_legitimate_authentication(self):
        """Verify that registered devices successfully authenticate and receive signed tokens."""
        ok, token, msg, _ = self.gateway.authenticate_device(self.sensor)
        self.assertTrue(ok)
        self.assertIsNotNone(token)
        self.assertEqual(token.device_id, self.sensor.device_id)
        self.assertEqual(token.role, DeviceRole.SENSOR)
        self.assertTrue(len(token.signature) > 0)

    def test_unregistered_device_rejection(self):
        """Verify that an unregistered device is blocked at handshake."""
        rogue = IoTDevice("rogue-99", secrets.token_bytes(32), DeviceRole.SENSOR, self.sensor_attrs)
        ok, token, msg, _ = self.gateway.authenticate_device(rogue)
        self.assertFalse(ok)
        self.assertEqual(msg, "DEVICE_UNREGISTERED")
        self.assertIsNone(token)

    def test_invalid_signature_rejection(self):
        """Verify that forged cryptographic signatures are rejected."""
        ok, token, msg, _ = self.gateway.authenticate_device(self.sensor, tamper_sig="invalid_signature_hex")
        self.assertFalse(ok)
        self.assertEqual(msg, "CRYPTOGRAPHIC_SIGNATURE_MISMATCH")
        self.assertIsNone(token)

    def test_nonce_replay_attack_prevention(self):
        """Verify that intercepted nonces cannot be replayed."""
        _, nonce, _ = self.gateway.auth_server.generate_challenge(self.sensor.device_id)
        ts = time.time()
        sig = self.sensor.compute_challenge_response(nonce, ts)

        # First use: should succeed
        ok1, token1, _ = self.gateway.auth_server.verify_challenge_and_issue_token(
            self.sensor.device_id, nonce, ts, sig
        )
        self.assertTrue(ok1)

        # Replay: should be denied
        ok2, token2, err2 = self.gateway.auth_server.verify_challenge_and_issue_token(
            self.sensor.device_id, nonce, ts, sig
        )
        self.assertFalse(ok2)
        self.assertEqual(err2, "NONCE_REPLAY_DETECTED")

    def test_token_tampering_detection(self):
        """Verify that tampering with token claims fails cryptographic verification."""
        self.gateway.authenticate_device(self.sensor)
        tampered_token = SecurityToken(
            token_id=self.sensor.active_token.token_id,
            device_id=self.sensor.device_id,
            role=DeviceRole.GATEWAY_ADMIN,  # Escalated role
            attributes=self.sensor.active_token.attributes,
            issued_at=self.sensor.active_token.issued_at,
            expires_at=self.sensor.active_token.expires_at,
            signature=self.sensor.active_token.signature
        )
        req = {
            "device_id": self.sensor.device_id,
            "resource_id": "res:critical:power_grid_switch",
            "action": ActionType.EXECUTE,
            "token": tampered_token
        }
        decision, _, _ = self.gateway.process_access_request(req)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.decision, AccessDecisionType.DENY_TOKEN_INVALID)

    def test_rbac_policy_enforcement(self):
        """Verify RBAC: Sensor can write telemetry but cannot control power switch."""
        self.gateway.authenticate_device(self.sensor)
        
        # Authorized access
        req_allowed = self.sensor.create_access_request("res:telemetry:sensor_data", ActionType.WRITE)
        req_allowed["params"] = {"temp": 21.0, "humidity": 40.0}
        dec1, _, _ = self.gateway.process_access_request(req_allowed)
        self.assertTrue(dec1.allowed)
        self.assertEqual(dec1.decision, AccessDecisionType.ALLOW)

        # Unauthorized access (Sensor -> Power Grid)
        req_denied = self.sensor.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
        dec2, _, _ = self.gateway.process_access_request(req_denied)
        self.assertFalse(dec2.allowed)
        self.assertEqual(dec2.decision, AccessDecisionType.DENY_UNAUTHORIZED_ROLE)

    def test_abac_policy_enforcement(self):
        """Verify ABAC: Admin allowed locally, but denied from external network or with outdated firmware."""
        self.gateway.authenticate_device(self.admin)

        # Local authorized admin
        req_local = self.admin.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
        req_local["params"] = {"switch_state": "OPEN"}
        dec1, _, _ = self.gateway.process_access_request(req_local)
        self.assertTrue(dec1.allowed)

        # External WAN access denied by ABAC
        req_wan = self.admin.create_access_request(
            "res:critical:power_grid_switch",
            ActionType.EXECUTE,
            context_override={"network_zone": NetworkZone.EXTERNAL_WAN.value}
        )
        dec2, _, _ = self.gateway.process_access_request(req_wan)
        self.assertFalse(dec2.allowed)
        self.assertEqual(dec2.decision, AccessDecisionType.DENY_ATTRIBUTE_POLICY)

        # Low firmware version denied by ABAC
        req_fw = self.admin.create_access_request(
            "res:critical:power_grid_switch",
            ActionType.EXECUTE,
            context_override={"firmware_version": 1.0}
        )
        dec3, _, _ = self.gateway.process_access_request(req_fw)
        self.assertFalse(dec3.allowed)
        self.assertEqual(dec3.decision, AccessDecisionType.DENY_ATTRIBUTE_POLICY)

    def test_instant_revocation(self):
        """Verify that revoking a device immediately invalidates its token and blocks requests."""
        self.gateway.authenticate_device(self.admin)
        req = self.admin.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
        
        # Valid before revocation
        dec_pre, _, _ = self.gateway.process_access_request(req)
        self.assertTrue(dec_pre.allowed)

        # Trigger Revocation
        self.gateway.revoke_device(self.admin.device_id, "Host compromised")

        # Blocked after revocation
        dec_post, _, _ = self.gateway.process_access_request(req)
        self.assertFalse(dec_post.allowed)
        self.assertEqual(dec_post.decision, AccessDecisionType.DENY_REVOKED)

        # New handshake also blocked
        handshake_ok, _, handshake_msg, _ = self.gateway.authenticate_device(self.admin)
        self.assertFalse(handshake_ok)
        self.assertEqual(handshake_msg, "DEVICE_REVOKED")

    def test_evaluation_metrics_execution(self):
        """Verify that all tasks in the evaluator execute and meet quantitative requirements."""
        evaluator = SecurityEvaluator(iterations=50)
        results = evaluator.run_all_evaluations()

        # 1. Authentication time
        auth = results["authentication_time"]
        self.assertGreater(auth["mean_ms"], 0.0)
        self.assertLess(auth["mean_ms"], 50.0)  # Cryptographic handshake should be fast (<50ms)

        # 2. Prevention rate
        prev = results["unauthorized_access_prevention"]
        self.assertEqual(prev["prevention_rate_pct"], 100.0)
        self.assertEqual(prev["unauthorized_breaches"], 0)
        self.assertEqual(prev["legitimate_request_pass_rate_pct"], 100.0)

        # 3. Communication overhead
        overhead = results["communication_overhead"]
        self.assertGreater(overhead["authentication_handshake"]["total_handshake_bytes"], 0)
        self.assertGreater(overhead["resource_access"]["total_access_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
