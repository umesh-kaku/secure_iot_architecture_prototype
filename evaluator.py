"""
Performance and Security Evaluation Engine for Secure IoT Architecture.
Evaluates:
1. Authentication Time (Latency & Throughput across iterations)
2. Unauthorized-Access Prevention Rate (Across 12 attack vectors)
3. Communication Overhead (Byte payload breakdown and comparison)
"""
import time
import statistics
import secrets
from typing import Dict, List, Any

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


class SecurityEvaluator:
    """
    Automated benchmark and metrics evaluator for IoT security architecture.
    """
    def __init__(self, iterations: int = 500):
        self.iterations = iterations
        self.gateway = IoTGateway()
        self._setup_test_devices()

    def _setup_test_devices(self):
        # 1. Legitimate Sensor
        self.sensor_key = secrets.token_bytes(32)
        self.sensor_attrs = DeviceAttributes(
            device_type="temp_sensor",
            firmware_version=2.1,
            network_zone=NetworkZone.INTERNAL_IOT_LAN,
            location="Bldg-A_Zone-1",
            trust_score=95
        )
        self.sensor_device = IoTDevice(
            device_id="dev-sensor-01",
            secret_key=self.sensor_key,
            role=DeviceRole.SENSOR,
            attributes=self.sensor_attrs
        )
        self.gateway.register_device(
            self.sensor_device.device_id,
            self.sensor_key,
            self.sensor_device.role,
            self.sensor_attrs
        )

        # 2. Legitimate Industrial Actuator
        self.actuator_key = secrets.token_bytes(32)
        self.actuator_attrs = DeviceAttributes(
            device_type="valve_actuator",
            firmware_version=2.0,
            network_zone=NetworkZone.INTERNAL_IOT_LAN,
            location="PumpRoom-B",
            trust_score=90
        )
        self.actuator_device = IoTDevice(
            device_id="dev-actuator-01",
            secret_key=self.actuator_key,
            role=DeviceRole.ACTUATOR,
            attributes=self.actuator_attrs
        )
        self.gateway.register_device(
            self.actuator_device.device_id,
            self.actuator_key,
            self.actuator_device.role,
            self.actuator_attrs
        )

        # 3. Legitimate Gateway Administrator
        self.admin_key = secrets.token_bytes(32)
        self.admin_attrs = DeviceAttributes(
            device_type="admin_controller",
            firmware_version=2.5,
            network_zone=NetworkZone.INTERNAL_IOT_LAN,
            location="ControlRoom",
            trust_score=99
        )
        self.admin_device = IoTDevice(
            device_id="dev-admin-01",
            secret_key=self.admin_key,
            role=DeviceRole.GATEWAY_ADMIN,
            attributes=self.admin_attrs
        )
        self.gateway.register_device(
            self.admin_device.device_id,
            self.admin_key,
            self.admin_device.role,
            self.admin_attrs
        )

        # Authenticate baseline devices so active tokens are immediately available
        self.gateway.authenticate_device(self.sensor_device)
        self.gateway.authenticate_device(self.actuator_device)
        self.gateway.authenticate_device(self.admin_device)

    # =========================================================================
    # Task Evaluation 1: Authentication Time
    # =========================================================================
    def evaluate_authentication_time(self, trials: int = None) -> Dict[str, Any]:
        """
        Measures the end-to-end cryptographic challenge-response authentication latency.
        Includes Phase 1 request, Phase 2 nonce generation, Phase 3 HMAC signature,
        and Phase 4 verification and signed token generation.
        """
        n = trials or self.iterations
        latencies_ms: List[float] = []

        for _ in range(n):
            t_start = time.perf_counter()
            success, token, msg, overhead = self.gateway.authenticate_device(self.sensor_device)
            t_end = time.perf_counter()
            
            assert success, f"Handshake failed: {msg}"
            latencies_ms.append((t_end - t_start) * 1000.0)

        latencies_sorted = sorted(latencies_ms)
        mean_lat = statistics.mean(latencies_ms)
        median_lat = statistics.median(latencies_ms)
        stdev_lat = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0.0
        min_lat = min(latencies_ms)
        max_lat = max(latencies_ms)
        p95_lat = latencies_sorted[int(0.95 * len(latencies_sorted))]
        p99_lat = latencies_sorted[int(0.99 * len(latencies_sorted))]
        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

        return {
            "trials": n,
            "mean_ms": mean_lat,
            "median_ms": median_lat,
            "stdev_ms": stdev_lat,
            "min_ms": min_lat,
            "max_ms": max_lat,
            "p95_ms": p95_lat,
            "p99_ms": p99_lat,
            "throughput_handshakes_per_sec": throughput
        }

    # =========================================================================
    # Task Evaluation 2: Unauthorized-Access Prevention Rate
    # =========================================================================
    def evaluate_unauthorized_prevention_rate(self, trials_per_vector: int = 50) -> Dict[str, Any]:
        """
        Tests access control against a battery of unauthorized and adversarial scenarios.
        Evaluates detection and prevention across 12 distinct attack vectors.
        """
        # Ensure fresh tokens for base devices
        self.gateway.authenticate_device(self.sensor_device)
        self.gateway.authenticate_device(self.actuator_device)
        self.gateway.authenticate_device(self.admin_device)

        attack_vectors = [
            ("Unregistered/Rogue Device Handshake", self._sim_unregistered_device),
            ("Invalid Cryptographic Key/Signature", self._sim_forged_signature),
            ("Nonce Replay Attack", self._sim_replay_attack),
            ("Missing Token Request", self._sim_missing_token),
            ("Expired Token Access", self._sim_expired_token),
            ("Tampered Token Payload (Role Elevation)", self._sim_tampered_token),
            ("RBAC: Sensor executing Power Grid Switch", self._sim_rbac_sensor_power_switch),
            ("RBAC: Actuator configuring System Firmware", self._sim_rbac_actuator_firmware),
            ("RBAC: Read-only attempting WRITE Action", self._sim_rbac_invalid_action),
            ("ABAC: Access from Untrusted External WAN", self._sim_abac_untrusted_zone),
            ("ABAC: Outdated Firmware on Critical Resource", self._sim_abac_outdated_firmware),
            ("ABAC: Degraded Device Trust Score", self._sim_abac_low_trust_score),
            ("Compromised & Revoked Device Access", self._sim_revoked_device),
            ("Revoked Capability Token Access", self._sim_revoked_token),
        ]

        results_by_vector = {}
        total_attempts = 0
        total_blocked = 0

        for vector_name, sim_func in attack_vectors:
            blocked_count = 0
            for _ in range(trials_per_vector):
                was_blocked = sim_func()
                if was_blocked:
                    blocked_count += 1
            
            rate = (blocked_count / trials_per_vector) * 100.0
            results_by_vector[vector_name] = {
                "trials": trials_per_vector,
                "blocked": blocked_count,
                "allowed": trials_per_vector - blocked_count,
                "prevention_rate_pct": rate
            }
            total_attempts += trials_per_vector
            total_blocked += blocked_count

        overall_rate = (total_blocked / total_attempts) * 100.0 if total_attempts > 0 else 0.0

        # Also verify baseline legitimate access (ensure zero false rejections)
        legit_trials = trials_per_vector
        legit_allowed = 0
        for _ in range(legit_trials):
            req = self.sensor_device.create_access_request(
                resource_id="res:telemetry:sensor_data",
                action=ActionType.WRITE,
                context_override=None
            )
            req["params"] = {"temp": 24.2, "humidity": 48.0}
            decision, _, _ = self.gateway.process_access_request(req)
            if decision.allowed:
                legit_allowed += 1

        legit_pass_rate = (legit_allowed / legit_trials) * 100.0

        return {
            "total_unauthorized_attempts": total_attempts,
            "blocked_unauthorized_attempts": total_blocked,
            "unauthorized_breaches": total_attempts - total_blocked,
            "prevention_rate_pct": overall_rate,
            "legitimate_request_pass_rate_pct": legit_pass_rate,
            "vector_details": results_by_vector
        }

    # --- Attack Simulation Helpers ---
    def _sim_unregistered_device(self) -> bool:
        rogue = IoTDevice(
            device_id=f"rogue-{secrets.token_hex(4)}",
            secret_key=secrets.token_bytes(32),
            role=DeviceRole.SENSOR,
            attributes=self.sensor_attrs
        )
        success, _, _, _ = self.gateway.authenticate_device(rogue)
        return not success  # Blocked if handshake failed

    def _sim_forged_signature(self) -> bool:
        success, _, _, _ = self.gateway.authenticate_device(
            self.sensor_device,
            tamper_sig="deadbeef" * 8
        )
        return not success

    def _sim_replay_attack(self) -> bool:
        # Request valid challenge
        _, nonce, _ = self.gateway.auth_server.generate_challenge(self.sensor_device.device_id)
        # Use once legitimately
        ts = time.time()
        sig = self.sensor_device.compute_challenge_response(nonce, ts)
        self.gateway.auth_server.verify_challenge_and_issue_token(
            self.sensor_device.device_id, nonce, ts, sig
        )
        # Attempt replay with exact same nonce
        replay_success, _, _ = self.gateway.auth_server.verify_challenge_and_issue_token(
            self.sensor_device.device_id, nonce, ts, sig
        )
        return not replay_success

    def _sim_missing_token(self) -> bool:
        req = {
            "device_id": self.sensor_device.device_id,
            "resource_id": "res:telemetry:sensor_data",
            "action": ActionType.READ,
            "token": None
        }
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_expired_token(self) -> bool:
        # Create an expired token
        expired_token = SecurityToken(
            token_id="tok-exp-01",
            device_id=self.sensor_device.device_id,
            role=DeviceRole.SENSOR,
            attributes=self.sensor_attrs.to_dict(),
            issued_at=time.time() - 600,
            expires_at=time.time() - 300
        )
        expired_token.signature = self.gateway.auth_server._sign_token(expired_token)
        req = {
            "device_id": self.sensor_device.device_id,
            "resource_id": "res:telemetry:sensor_data",
            "action": ActionType.WRITE,
            "token": expired_token
        }
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_tampered_token(self) -> bool:
        if not self.sensor_device.active_token:
            self.gateway.authenticate_device(self.sensor_device)

        # Device takes sensor token, changes role to GATEWAY_ADMIN without signature key
        tampered_token = SecurityToken(
            token_id=self.sensor_device.active_token.token_id,
            device_id=self.sensor_device.device_id,
            role=DeviceRole.GATEWAY_ADMIN,  # Tampered
            attributes=self.sensor_device.active_token.attributes,
            issued_at=self.sensor_device.active_token.issued_at,
            expires_at=self.sensor_device.active_token.expires_at,
            signature=self.sensor_device.active_token.signature  # Original signature
        )
        req = {
            "device_id": self.sensor_device.device_id,
            "resource_id": "res:critical:power_grid_switch",
            "action": ActionType.EXECUTE,
            "token": tampered_token
        }
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_rbac_sensor_power_switch(self) -> bool:
        # Sensor attempts to flip critical power grid switch
        req = self.sensor_device.create_access_request(
            resource_id="res:critical:power_grid_switch",
            action=ActionType.EXECUTE
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_rbac_actuator_firmware(self) -> bool:
        # Actuator attempts to flash firmware
        req = self.actuator_device.create_access_request(
            resource_id="res:system:firmware_update",
            action=ActionType.EXECUTE
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_rbac_invalid_action(self) -> bool:
        # Sensor attempts to execute code on sensor telemetry store
        req = self.sensor_device.create_access_request(
            resource_id="res:telemetry:sensor_data",
            action=ActionType.EXECUTE
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_abac_untrusted_zone(self) -> bool:
        # Admin connects from untrusted EXTERNAL_WAN to flip power grid switch
        req = self.admin_device.create_access_request(
            resource_id="res:critical:power_grid_switch",
            action=ActionType.EXECUTE,
            context_override={"network_zone": NetworkZone.EXTERNAL_WAN.value}
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_abac_outdated_firmware(self) -> bool:
        # Admin with outdated firmware (v1.0 instead of required v2.0)
        req = self.admin_device.create_access_request(
            resource_id="res:critical:power_grid_switch",
            action=ActionType.EXECUTE,
            context_override={"firmware_version": 1.0}
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_abac_low_trust_score(self) -> bool:
        # Admin device with compromised/degraded trust score of 30 (required 85)
        req = self.admin_device.create_access_request(
            resource_id="res:critical:power_grid_switch",
            action=ActionType.EXECUTE,
            context_override={"trust_score": 30}
        )
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_revoked_device(self) -> bool:
        # Create a device and revoke it
        dev_id = f"dev-compromised-{secrets.token_hex(4)}"
        dev_key = secrets.token_bytes(32)
        dev = IoTDevice(dev_id, dev_key, DeviceRole.GATEWAY_ADMIN, self.admin_attrs)
        self.gateway.register_device(dev_id, dev_key, dev.role, self.admin_attrs)
        self.gateway.authenticate_device(dev)
        
        # Trigger revocation
        self.gateway.revoke_device(dev_id, "Malware signature found")
        
        # Attempt access
        req = dev.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    def _sim_revoked_token(self) -> bool:
        # Create valid device & token
        dev_id = f"dev-tok-rev-{secrets.token_hex(4)}"
        dev_key = secrets.token_bytes(32)
        dev = IoTDevice(dev_id, dev_key, DeviceRole.GATEWAY_ADMIN, self.admin_attrs)
        self.gateway.register_device(dev_id, dev_key, dev.role, self.admin_attrs)
        _, token, _, _ = self.gateway.authenticate_device(dev)
        
        # Revoke token specifically
        self.gateway.revoke_token(token.token_id, dev_id, "Session invalidated")
        
        # Attempt access
        req = dev.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
        decision, _, _ = self.gateway.process_access_request(req)
        return not decision.allowed

    # =========================================================================
    # Task Evaluation 3: Communication Overhead
    # =========================================================================
    def evaluate_communication_overhead(self) -> Dict[str, Any]:
        """
        Calculates exact network transmission overhead in bytes for:
        1. Authentication Protocol (Phase 1 to Phase 4)
        2. Authorized Resource Access Protocol
        3. Baseline Insecure/Unauthenticated IoT baseline comparison
        """
        # 1. Measure Authentication Overhead
        _, token, _, auth_overhead = self.gateway.authenticate_device(self.sensor_device)

        # 2. Measure Resource Access Overhead
        access_req = self.sensor_device.create_access_request(
            resource_id="res:telemetry:sensor_data",
            action=ActionType.WRITE
        )
        access_req["params"] = {"temp": 22.4, "humidity": 50.1}
        _, _, access_overhead = self.gateway.process_access_request(access_req)

        # 3. Compare with Baseline Insecure / Plaintext IoT Request
        # Insecure IoT typically sends raw JSON: {"device_id": "...", "temp": 22.4, "humidity": 50.1} without tokens/crypto
        baseline_payload = {
            "device_id": self.sensor_device.device_id,
            "resource_id": "res:telemetry:sensor_data",
            "action": "write",
            "params": {"temp": 22.4, "humidity": 50.1}
        }
        baseline_bytes = len(str(baseline_payload).encode("utf-8"))
        baseline_resp_bytes = len(b'{"status": "ok"}')
        baseline_total = baseline_bytes + baseline_resp_bytes

        secured_access_total = access_overhead["total_access_bytes"]
        security_overhead_bytes = secured_access_total - baseline_total
        overhead_ratio = (secured_access_total / baseline_total) if baseline_total > 0 else 1.0

        return {
            "authentication_handshake": {
                "phase1_request_bytes": auth_overhead["phase1_request_bytes"],
                "phase2_challenge_bytes": auth_overhead["phase2_challenge_bytes"],
                "phase3_response_bytes": auth_overhead["phase3_response_bytes"],
                "phase4_token_issue_bytes": auth_overhead["phase4_token_issue_bytes"],
                "total_handshake_bytes": auth_overhead["total_auth_bytes"]
            },
            "resource_access": {
                "request_bytes": access_overhead["request_bytes"],
                "token_carrier_bytes": access_overhead["token_bytes"],
                "response_bytes": access_overhead["response_bytes"],
                "total_access_bytes": secured_access_total
            },
            "baseline_comparison": {
                "insecure_baseline_bytes": baseline_total,
                "secured_access_bytes": secured_access_total,
                "additional_security_overhead_bytes": security_overhead_bytes,
                "overhead_multiplier": overhead_ratio
            }
        }

    # =========================================================================
    # Unified Evaluation Runner
    # =========================================================================
    def run_all_evaluations(self) -> Dict[str, Any]:
        """Runs the complete suite of performance and security metrics."""
        auth_metrics = self.evaluate_authentication_time()
        prevention_metrics = self.evaluate_unauthorized_prevention_rate()
        overhead_metrics = self.evaluate_communication_overhead()

        return {
            "authentication_time": auth_metrics,
            "unauthorized_access_prevention": prevention_metrics,
            "communication_overhead": overhead_metrics
        }
