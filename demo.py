"""
Interactive / Automated Demonstration Script for Secure IoT Architecture.
Demonstrates:
1. Cryptographic Device Identities and Challenge-Response Authentication.
2. Fine-grained RBAC and ABAC Policy Decisions.
3. Dynamic Device Compromise Detection and Instant Access Revocation.
4. Comprehensive Quantitative Evaluation (Latency, Prevention Rate, Overhead).
"""
import secrets
import time

from models import (
    DeviceRole,
    DeviceAttributes,
    NetworkZone,
    ActionType,
    AccessDecisionType
)
from gateway import IoTGateway
from device import IoTDevice
from evaluator import SecurityEvaluator


def print_banner(title: str):
    line = "=" * 78
    print(f"\n{line}")
    print(f"  {title.upper()}")
    print(f"{line}")


def print_section(title: str):
    print(f"\n--- {title} ---")


def run_demonstration():
    print_banner("Secure IoT Architecture Demonstration & Prototype")
    print("Zero-Trust Architecture Combining Device Authentication, RBAC, ABAC, & Instant Revocation\n")

    # -------------------------------------------------------------------------
    # Step 1: Initialize Gateway and Provision Device Identities
    # -------------------------------------------------------------------------
    print_section("Step 1: Cryptographic Identity Provisioning")
    gateway = IoTGateway(token_ttl_seconds=300)

    # 1. IoT Temperature Sensor
    sensor_key = secrets.token_bytes(32)
    sensor_attrs = DeviceAttributes(
        device_type="temp_humidity_sensor",
        firmware_version=2.1,
        network_zone=NetworkZone.INTERNAL_IOT_LAN,
        location="Zone-A_CleanRoom",
        trust_score=95
    )
    sensor_dev = IoTDevice("sensor-node-01", sensor_key, DeviceRole.SENSOR, sensor_attrs)
    gateway.register_device(sensor_dev.device_id, sensor_key, sensor_dev.role, sensor_attrs)
    print(f"[*] Registered Device: {sensor_dev.device_id:<18} | Role: {sensor_dev.role.value:<10} | Zone: {sensor_attrs.network_zone.value}")

    # 2. Industrial Water Actuator
    actuator_key = secrets.token_bytes(32)
    actuator_attrs = DeviceAttributes(
        device_type="valve_controller",
        firmware_version=2.0,
        network_zone=NetworkZone.INTERNAL_IOT_LAN,
        location="Zone-B_CoolingTower",
        trust_score=90
    )
    actuator_dev = IoTDevice("actuator-pump-01", actuator_key, DeviceRole.ACTUATOR, actuator_attrs)
    gateway.register_device(actuator_dev.device_id, actuator_key, actuator_dev.role, actuator_attrs)
    print(f"[*] Registered Device: {actuator_dev.device_id:<18} | Role: {actuator_dev.role.value:<10} | Zone: {actuator_attrs.network_zone.value}")

    # 3. Gateway Admin Controller
    admin_key = secrets.token_bytes(32)
    admin_attrs = DeviceAttributes(
        device_type="scada_admin_terminal",
        firmware_version=2.5,
        network_zone=NetworkZone.INTERNAL_IOT_LAN,
        location="HQ_OperationsCenter",
        trust_score=98
    )
    admin_dev = IoTDevice("admin-terminal-01", admin_key, DeviceRole.GATEWAY_ADMIN, admin_attrs)
    gateway.register_device(admin_dev.device_id, admin_key, admin_dev.role, admin_attrs)
    print(f"[*] Registered Device: {admin_dev.device_id:<18} | Role: {admin_dev.role.value:<10} | Zone: {admin_attrs.network_zone.value}")

    # 4. Rogue / Attacker Device
    rogue_dev = IoTDevice(
        "rogue-device-66",
        secrets.token_bytes(32),
        DeviceRole.GATEWAY_ADMIN,
        DeviceAttributes("fake_controller", 1.0, NetworkZone.EXTERNAL_WAN, "Unknown", 10)
    )
    print(f"[!] Unregistered Device: {rogue_dev.device_id:<18} | Claims Role: {rogue_dev.role.value:<10} (Adversary)")

    # -------------------------------------------------------------------------
    # Step 2: Challenge-Response Authentication
    # -------------------------------------------------------------------------
    print_section("Step 2: Mutual Challenge-Response Handshake")
    
    # Authenticate Sensor
    s_ok, s_tok, s_msg, s_bytes = gateway.authenticate_device(sensor_dev)
    print(f"[+] Sensor Handshake: {'SUCCESS' if s_ok else 'FAILED'} -> Token ID: {s_tok.token_id} (Issued, Signed)")

    # Authenticate Actuator
    a_ok, a_tok, a_msg, a_bytes = gateway.authenticate_device(actuator_dev)
    print(f"[+] Actuator Handshake: {'SUCCESS' if a_ok else 'FAILED'} -> Token ID: {a_tok.token_id}")

    # Authenticate Admin
    adm_ok, adm_tok, adm_msg, adm_bytes = gateway.authenticate_device(admin_dev)
    print(f"[+] Admin Handshake: {'SUCCESS' if adm_ok else 'FAILED'} -> Token ID: {adm_tok.token_id}")

    # Adversary Authentication Attempt
    r_ok, r_tok, r_msg, r_bytes = gateway.authenticate_device(rogue_dev)
    print(f"[-] Rogue Device Handshake: {'ALLOWED (FAIL!)' if r_ok else 'BLOCKED'} -> Reason: {r_msg}")

    # Replay Attack Attempt
    _, replay_nonce, _ = gateway.auth_server.generate_challenge(sensor_dev.device_id)
    t_now = time.time()
    sig = sensor_dev.compute_challenge_response(replay_nonce, t_now)
    gateway.auth_server.verify_challenge_and_issue_token(sensor_dev.device_id, replay_nonce, t_now, sig)
    # Replay
    rep_ok, _, rep_msg = gateway.auth_server.verify_challenge_and_issue_token(sensor_dev.device_id, replay_nonce, t_now, sig)
    print(f"[-] Replay Attack with Reused Nonce: {'ALLOWED (FAIL!)' if rep_ok else 'BLOCKED'} -> Reason: {rep_msg}")

    # -------------------------------------------------------------------------
    # Step 3: Access Control (RBAC + ABAC Policy Enforcement)
    # -------------------------------------------------------------------------
    print_section("Step 3: RBAC & ABAC Policy Decision Engine in Action")

    # Scenario 3.1: Legitimate Sensor writes telemetry (Granted)
    req = sensor_dev.create_access_request("res:telemetry:sensor_data", ActionType.WRITE)
    req["params"] = {"temp": 24.8, "humidity": 52.0}
    dec, data, _ = gateway.process_access_request(req)
    print(f"\n[Case 3.1] Sensor writing telemetry:")
    print(f"    Decision: {dec.decision.value} (Allowed={dec.allowed}) | State: {data}")

    # Scenario 3.2: Sensor attempts to trip Power Grid Relay (RBAC Violation)
    req = sensor_dev.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
    req["params"] = {"switch_state": "TRIPPED"}
    dec, _, _ = gateway.process_access_request(req)
    print(f"\n[Case 3.2] Sensor attempting to trip Power Grid Switch (Privilege Escalation):")
    print(f"    Decision: {dec.decision.value} (Allowed={dec.allowed})")
    print(f"    Enforcement: {dec.reason}")

    # Scenario 3.3: Admin executes Power Grid switch from internal network (Granted)
    req = admin_dev.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
    req["params"] = {"switch_state": "ACTIVE_ISOLATED"}
    dec, data, _ = gateway.process_access_request(req)
    print(f"\n[Case 3.3] Admin executing Power Grid Switch from Internal LAN:")
    print(f"    Decision: {dec.decision.value} (Allowed={dec.allowed}) | Result: {data}")

    # Scenario 3.4: Admin attempts access from External WAN (ABAC Violation: Network Zone)
    req = admin_dev.create_access_request(
        "res:critical:power_grid_switch",
        ActionType.EXECUTE,
        context_override={"network_zone": NetworkZone.EXTERNAL_WAN.value}
    )
    dec, _, _ = gateway.process_access_request(req)
    print(f"\n[Case 3.4] Admin attempting Critical access from External WAN (ABAC Context Check):")
    print(f"    Decision: {dec.decision.value} (Allowed={dec.allowed})")
    print(f"    Enforcement: {dec.reason}")

    # Scenario 3.5: Admin terminal with outdated firmware v1.2 (ABAC Violation: Min Firmware 2.0)
    req = admin_dev.create_access_request(
        "res:critical:power_grid_switch",
        ActionType.EXECUTE,
        context_override={"firmware_version": 1.2}
    )
    dec, _, _ = gateway.process_access_request(req)
    print(f"\n[Case 3.5] Admin device running vulnerable Firmware v1.2 (ABAC Firmware Policy):")
    print(f"    Decision: {dec.decision.value} (Allowed={dec.allowed})")
    print(f"    Enforcement: {dec.reason}")

    # -------------------------------------------------------------------------
    # Step 4: Access Revocation & Compromised Device Handling
    # -------------------------------------------------------------------------
    print_section("Step 4: Dynamic Anomaly Detection & Instant Access Revocation")

    print("[*] Admin terminal currently holds valid access token.")
    req = admin_dev.create_access_request("res:system:firmware_update", ActionType.EXECUTE)
    req["params"] = {"patch": "PATCH-SECURITY-V3"}
    dec, data, _ = gateway.process_access_request(req)
    print(f"    Pre-revocation request status: {dec.decision.value} (Allowed={dec.allowed})")

    # Anomaly / Compromise Detected: Gateway activates Revocation
    print("\n[!] ALERT: Security Operations Center reports 'admin-terminal-01' compromised by malware!")
    print("[!] Triggering Gateway Revocation API: Instant Device & Token Blacklisting...")
    gateway.revoke_device(admin_dev.device_id, reason="Malware intrusion signature detected on host")
    print(f"    Blacklist updated in Revocation Manager: Device '{admin_dev.device_id}' flagged REVOKED.")

    # Subsequent access attempt using existing, unexpired token
    req_post = admin_dev.create_access_request("res:critical:power_grid_switch", ActionType.EXECUTE)
    dec_post, _, _ = gateway.process_access_request(req_post)
    print(f"\n[Case 4.1] Compromised Admin attempting Power Grid control with unexpired token:")
    print(f"    Decision: {dec_post.decision.value} (Allowed={dec_post.allowed})")
    print(f"    Enforcement: {dec_post.reason}")

    # Attempting new authentication handshake while revoked
    auth_retry_ok, _, auth_retry_msg, _ = gateway.authenticate_device(admin_dev)
    print(f"\n[Case 4.2] Compromised Admin attempting new authentication handshake:")
    print(f"    Handshake: {'ALLOWED (FAIL!)' if auth_retry_ok else 'BLOCKED'} -> Reason: {auth_retry_msg}")

    # -------------------------------------------------------------------------
    # Step 5: Full Evaluation Suite Execution
    # -------------------------------------------------------------------------
    print_banner("Step 5: Quantitative Evaluation of Security Metrics")
    evaluator = SecurityEvaluator(iterations=1000)

    # 1. Authentication Time Evaluation
    print("\n[Task Metric 1] Evaluating Authentication Time (1,000 Handshakes)...")
    t_metrics = evaluator.evaluate_authentication_time(1000)
    print(f"    Mean Authentication Time : {t_metrics['mean_ms']:.4f} ms")
    print(f"    Median Time              : {t_metrics['median_ms']:.4f} ms")
    print(f"    Min / Max Time           : {t_metrics['min_ms']:.4f} ms / {t_metrics['max_ms']:.4f} ms")
    print(f"    Standard Deviation       : {t_metrics['stdev_ms']:.4f} ms")
    print(f"    95th Percentile (P95)    : {t_metrics['p95_ms']:.4f} ms")
    print(f"    99th Percentile (P99)    : {t_metrics['p99_ms']:.4f} ms")
    print(f"    Authentication Throughput: {t_metrics['throughput_handshakes_per_sec']:.1f} handshakes/sec")

    # 2. Unauthorized-Access Prevention Rate Evaluation
    print("\n[Task Metric 2] Evaluating Unauthorized-Access Prevention Rate (14 Threat Scenarios)...")
    p_metrics = evaluator.evaluate_unauthorized_prevention_rate(trials_per_vector=100)
    print(f"\n    {'-'*74}")
    print(f"    {'Threat Scenario':<44} | {'Trials':<7} | {'Blocked':<8} | {'Rate'}")
    print(f"    {'-'*74}")
    for vec, data in p_metrics["vector_details"].items():
        print(f"    {vec:<44} | {data['trials']:<7} | {data['blocked']:<8} | {data['prevention_rate_pct']:.1f}%")
    print(f"    {'-'*74}")
    print(f"    Total Unauthorized Attempts Tested : {p_metrics['total_unauthorized_attempts']}")
    print(f"    Blocked Attempts                   : {p_metrics['blocked_unauthorized_attempts']}")
    print(f"    Security Breaches (False Negatives): {p_metrics['unauthorized_breaches']}")
    print(f"    OVERALL PREVENTION RATE            : {p_metrics['prevention_rate_pct']:.2f}%")
    print(f"    Legitimate Request Pass Rate       : {p_metrics['legitimate_request_pass_rate_pct']:.2f}%")

    # 3. Communication Overhead Evaluation
    print("\n[Task Metric 3] Evaluating Network Communication Overhead...")
    o_metrics = evaluator.evaluate_communication_overhead()
    hs = o_metrics["authentication_handshake"]
    acc = o_metrics["resource_access"]
    base = o_metrics["baseline_comparison"]

    print(f"    Handshake Payload Breakdown:")
    print(f"      - Phase 1 (Device Hello Request)     : {hs['phase1_request_bytes']} bytes")
    print(f"      - Phase 2 (Gateway Challenge Nonce)  : {hs['phase2_challenge_bytes']} bytes")
    print(f"      - Phase 3 (Client Response Signature): {hs['phase3_response_bytes']} bytes")
    print(f"      - Phase 4 (Signed Token Issuance)    : {hs['phase4_token_issue_bytes']} bytes")
    print(f"      - Total Handshake Overhead           : {hs['total_handshake_bytes']} bytes")
    print(f"\n    Resource Access Payload Breakdown:")
    print(f"      - Request Payload                    : {acc['request_bytes']} bytes (Token Carrier: {acc['token_carrier_bytes']} bytes)")
    print(f"      - Gateway Response Payload           : {acc['response_bytes']} bytes")
    print(f"      - Total Access Overhead              : {acc['total_access_bytes']} bytes")
    print(f"\n    Comparative Overhead Analysis:")
    print(f"      - Insecure Baseline Plaintext IoT    : {base['insecure_baseline_bytes']} bytes")
    print(f"      - Secured IoT Access Transaction     : {base['secured_access_bytes']} bytes")
    print(f"      - Net Cryptographic Security Premium : +{base['additional_security_overhead_bytes']} bytes ({base['overhead_multiplier']:.2f}x)")

    print_banner("Demonstration & Evaluation Complete: All Tasks Successfully Achieved")


if __name__ == "__main__":
    run_demonstration()
