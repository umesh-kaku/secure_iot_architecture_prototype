"""
HTTP Backend Server for Secure IoT Architecture Web GUI.
Uses Python standard library (http.server) - zero external dependencies.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import secrets
import time
import urllib.parse
from typing import Dict, Any, List

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


class IoTState:
    """Manages the in-memory state and log history for the web GUI."""
    def __init__(self):
        self.gateway = IoTGateway(token_ttl_seconds=300)
        self.devices: Dict[str, IoTDevice] = {}
        self.audit_logs: List[Dict[str, Any]] = []
        self._seed_default_devices()

    def log(self, category: str, message: str, status: str = "INFO", details: Any = None):
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "category": category,
            "message": message,
            "status": status,
            "details": details
        }
        self.audit_logs.insert(0, entry)
        if len(self.audit_logs) > 50:
            self.audit_logs.pop()

    def _seed_default_devices(self):
        # 1. Environmental Sensor
        s_key = secrets.token_bytes(32)
        s_attrs = DeviceAttributes("temp_sensor", 2.1, NetworkZone.INTERNAL_IOT_LAN, "Zone-A_CleanRoom", 95)
        sensor = IoTDevice("dev-sensor-01", s_key, DeviceRole.SENSOR, s_attrs)
        self.devices[sensor.device_id] = sensor
        self.gateway.register_device(sensor.device_id, s_key, sensor.role, s_attrs)

        # 2. Water Actuator
        a_key = secrets.token_bytes(32)
        a_attrs = DeviceAttributes("water_valve", 2.0, NetworkZone.INTERNAL_IOT_LAN, "PumpRoom-B", 90)
        actuator = IoTDevice("dev-actuator-01", a_key, DeviceRole.ACTUATOR, a_attrs)
        self.devices[actuator.device_id] = actuator
        self.gateway.register_device(actuator.device_id, a_key, actuator.role, a_attrs)

        # 3. Gateway Admin Controller
        adm_key = secrets.token_bytes(32)
        adm_attrs = DeviceAttributes("admin_terminal", 2.5, NetworkZone.INTERNAL_IOT_LAN, "HQ_ControlRoom", 98)
        admin = IoTDevice("dev-admin-01", adm_key, DeviceRole.GATEWAY_ADMIN, adm_attrs)
        self.devices[admin.device_id] = admin
        self.gateway.register_device(admin.device_id, adm_key, admin.role, adm_attrs)

        # 4. Rogue / Attacker Device (Unregistered in Gateway)
        rogue_key = secrets.token_bytes(32)
        rogue_attrs = DeviceAttributes("fake_controller", 1.0, NetworkZone.EXTERNAL_WAN, "Unknown", 10)
        rogue = IoTDevice("dev-rogue-99", rogue_key, DeviceRole.GATEWAY_ADMIN, rogue_attrs)
        self.devices[rogue.device_id] = rogue
        # Note: NOT registered in self.gateway!

        self.log("INIT", "Default devices provisioned in security architecture.")

    def get_state_summary(self) -> Dict[str, Any]:
        dev_list = []
        for dev_id, dev in self.devices.items():
            is_revoked = self.gateway.revocation_manager.is_device_revoked(dev_id)
            has_token = dev.active_token is not None and not dev.active_token.is_expired()
            is_registered = self.gateway.auth_server.get_device_info(dev_id) is not None

            dev_list.append({
                "device_id": dev_id,
                "role": dev.role.value,
                "device_type": dev.attributes.device_type,
                "firmware_version": dev.attributes.firmware_version,
                "network_zone": dev.attributes.network_zone.value,
                "trust_score": dev.attributes.trust_score,
                "location": dev.attributes.location,
                "is_registered": is_registered,
                "is_revoked": is_revoked,
                "has_valid_token": has_token,
                "token_id": dev.active_token.token_id if has_token else None,
                "token_expires_at": time.strftime("%H:%M:%S", time.localtime(dev.active_token.expires_at)) if has_token else None
            })

        # Resources list
        res_list = []
        for r_id, r in self.gateway.pdp._resources.items():
            res_list.append({
                "resource_id": r.resource_id,
                "name": r.name,
                "description": r.description,
                "allowed_roles": [role.value for role in r.allowed_roles],
                "allowed_actions": [act.value for act in r.allowed_actions],
                "min_firmware": r.min_firmware,
                "allowed_zones": [z.value for z in r.allowed_zones],
                "min_trust_score": r.min_trust_score,
                "is_critical": r.is_critical,
                "current_state": self.gateway._resource_state.get(r_id, {})
            })

        revoked_details = []
        for r_dev in self.gateway.revocation_manager._revoked_devices.values():
            revoked_details.append({
                "device_id": r_dev["device_id"],
                "reason": r_dev["reason"],
                "timestamp": time.strftime("%H:%M:%S", time.localtime(r_dev["timestamp"]))
            })

        return {
            "devices": dev_list,
            "resources": res_list,
            "revoked_devices": revoked_details,
            "audit_logs": self.audit_logs
        }


# Global shared instance
STATE = IoTState()


class IoTRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, filepath: str, content_type: str):
        if not os.path.exists(filepath):
            self.send_error(404, "File not found")
            return
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            self._serve_file("static/index.html", "text/html; charset=utf-8")
        elif path == "/style.css":
            self._serve_file("static/style.css", "text/css; charset=utf-8")
        elif path == "/app.js":
            self._serve_file("static/app.js", "application/javascript; charset=utf-8")
        elif path == "/api/state":
            self._send_json(STATE.get_state_summary())
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            payload = {}

        if path == "/api/auth":
            self._handle_auth(payload)
        elif path == "/api/access":
            self._handle_access(payload)
        elif path == "/api/revoke":
            self._handle_revoke(payload)
        elif path == "/api/register":
            self._handle_register(payload)
        elif path == "/api/simulate":
            self._handle_simulate(payload)
        elif path == "/api/evaluate":
            self._handle_evaluate(payload)
        else:
            self.send_error(404, "Unknown endpoint")

    def _handle_auth(self, payload: Dict[str, Any]):
        dev_id = payload.get("device_id")
        dev = STATE.devices.get(dev_id)
        if not dev:
            self._send_json({"success": False, "message": f"Device '{dev_id}' not found in clients."}, 400)
            return

        tamper_sig = payload.get("tamper_signature")
        tamper_nonce = payload.get("tamper_nonce")

        success, token, msg, overhead = STATE.gateway.authenticate_device(
            dev,
            tamper_nonce=tamper_nonce,
            tamper_sig=tamper_sig
        )

        log_status = "SUCCESS" if success else "DENIED"
        STATE.log("AUTH", f"Auth Handshake for '{dev_id}': {msg}", status=log_status, details=overhead)

        resp = {
            "success": success,
            "message": msg,
            "token_id": token.token_id if token else None,
            "token_role": token.role.value if token else None,
            "token_signature": token.signature if token else None,
            "overhead": overhead
        }
        self._send_json(resp)

    def _handle_access(self, payload: Dict[str, Any]):
        dev_id = payload.get("device_id")
        res_id = payload.get("resource_id")
        action_str = payload.get("action", "read")
        context_override = payload.get("context_override")
        params = payload.get("params")

        dev = STATE.devices.get(dev_id)
        if not dev:
            self._send_json({"success": False, "message": "Unknown device"}, 400)
            return

        try:
            action = ActionType(action_str)
        except Exception:
            action = ActionType.READ

        # Build access request
        req = dev.create_access_request(res_id, action, context_override=context_override)
        if params:
            req["params"] = params

        # Handle explicit token tampering simulation
        if payload.get("tamper_token_role"):
            if dev.active_token:
                # Tamper role claim
                tampered = SecurityToken(
                    token_id=dev.active_token.token_id,
                    device_id=dev.active_token.device_id,
                    role=DeviceRole(payload["tamper_token_role"]),
                    attributes=dev.active_token.attributes,
                    issued_at=dev.active_token.issued_at,
                    expires_at=dev.active_token.expires_at,
                    signature=dev.active_token.signature
                )
                req["token"] = tampered

        decision, data, overhead = STATE.gateway.process_access_request(req)
        log_status = "ALLOW" if decision.allowed else "DENY"
        STATE.log(
            "ACCESS",
            f"Access to '{res_id}' ({action.value}) by '{dev_id}': {decision.decision.value}",
            status=log_status,
            details=decision.reason
        )

        resp = {
            "allowed": decision.allowed,
            "decision": decision.decision.value,
            "reason": decision.reason,
            "resource_state": data,
            "overhead": overhead
        }
        self._send_json(resp)

    def _handle_revoke(self, payload: Dict[str, Any]):
        dev_id = payload.get("device_id")
        reason = payload.get("reason", "Manually revoked by administrator")
        if not dev_id:
            self._send_json({"success": False, "message": "Missing device_id"}, 400)
            return

        entry = STATE.gateway.revoke_device(dev_id, reason)
        STATE.log("REVOKE", f"Device '{dev_id}' REVOKED immediately. Reason: {reason}", status="ALERT")
        self._send_json({"success": True, "entry": entry})

    def _handle_register(self, payload: Dict[str, Any]):
        dev_id = payload.get("device_id", "").strip()
        role_str = payload.get("role", "sensor")
        fw = float(payload.get("firmware_version", 2.0))
        zone_str = payload.get("network_zone", "internal_iot_lan")
        trust = int(payload.get("trust_score", 90))
        loc = payload.get("location", "Lab-1")

        if not dev_id:
            self._send_json({"success": False, "message": "Device ID cannot be empty"}, 400)
            return

        key = secrets.token_bytes(32)
        role = DeviceRole(role_str)
        zone = NetworkZone(zone_str)
        attrs = DeviceAttributes("custom_iot_node", fw, zone, loc, trust)
        dev = IoTDevice(dev_id, key, role, attrs)
        STATE.devices[dev_id] = dev
        STATE.gateway.register_device(dev_id, key, role, attrs)

        STATE.log("REGISTER", f"Registered new device '{dev_id}' (Role: {role.value})", status="SUCCESS")
        self._send_json({"success": True, "device_id": dev_id})

    def _handle_simulate(self, payload: Dict[str, Any]):
        attack_type = payload.get("attack_type")
        evaluator = SecurityEvaluator(iterations=10)

        result = {}
        if attack_type == "rogue":
            blocked = evaluator._sim_unregistered_device()
            result = {
                "name": "Rogue/Unregistered Device Attack",
                "blocked": blocked,
                "description": "An adversary node with unknown identity attempts the handshake.",
                "outcome": "Handshake rejected at Gateway with 'DEVICE_UNREGISTERED'."
            }
        elif attack_type == "forged_sig":
            blocked = evaluator._sim_forged_signature()
            result = {
                "name": "Forged Cryptographic Signature",
                "blocked": blocked,
                "description": "Attacker supplies invalid HMAC signature.",
                "outcome": "Rejected with 'CRYPTOGRAPHIC_SIGNATURE_MISMATCH'."
            }
        elif attack_type == "replay":
            blocked = evaluator._sim_replay_attack()
            result = {
                "name": "Nonce Replay Attack",
                "blocked": blocked,
                "description": "Attacker intercepts and resends a previously used challenge nonce.",
                "outcome": "Rejected with 'NONCE_REPLAY_DETECTED'."
            }
        elif attack_type == "tamper_token":
            blocked = evaluator._sim_tampered_token()
            result = {
                "name": "Tampered Token Payload (Privilege Escalation)",
                "blocked": blocked,
                "description": "Attacker edits token claims to claim GATEWAY_ADMIN.",
                "outcome": "Cryptographic signature check fails -> DENY_TOKEN_INVALID."
            }
        elif attack_type == "rbac_escalation":
            blocked = evaluator._sim_rbac_sensor_power_switch()
            result = {
                "name": "RBAC Violation (Sensor -> Power Grid)",
                "blocked": blocked,
                "description": "Valid sensor attempts EXECUTE on Substation Power Grid Relay.",
                "outcome": "PEP Policy blocks access: DENY_UNAUTHORIZED_ROLE."
            }
        elif attack_type == "abac_zone":
            blocked = evaluator._sim_abac_untrusted_zone()
            result = {
                "name": "ABAC Violation (External WAN)",
                "blocked": blocked,
                "description": "Admin connects from untrusted EXTERNAL_WAN for critical relay.",
                "outcome": "ABAC Policy blocks access: DENY_ATTRIBUTE_POLICY."
            }
        elif attack_type == "abac_firmware":
            blocked = evaluator._sim_abac_outdated_firmware()
            result = {
                "name": "ABAC Violation (Outdated Firmware)",
                "blocked": blocked,
                "description": "Device running unpatched firmware v1.0 tries critical access.",
                "outcome": "ABAC Policy blocks access: Firmware version below minimum required."
            }
        elif attack_type == "revocation":
            blocked = evaluator._sim_revoked_device()
            result = {
                "name": "Compromised & Revoked Lockout",
                "blocked": blocked,
                "description": "Node reported compromised by SOC; gateway marks REVOKED.",
                "outcome": "All existing tokens and new handshakes blocked with DENY_REVOKED."
            }
        else:
            self._send_json({"success": False, "message": "Unknown attack type"}, 400)
            return

        STATE.log(
            "ATTACK_SIM",
            f"Simulated '{result['name']}': {'BLOCKED (Secure)' if result['blocked'] else 'BREACH'}",
            status="SUCCESS" if result['blocked'] else "BREACH"
        )
        self._send_json({"success": True, "result": result})

    def _handle_evaluate(self, payload: Dict[str, Any]):
        trials = int(payload.get("iterations", 300))
        evaluator = SecurityEvaluator(iterations=trials)
        res = evaluator.run_all_evaluations()
        STATE.log("EVALUATE", f"Completed full quantitative evaluation benchmark ({trials} trials).", status="SUCCESS")
        self._send_json({"success": True, "data": res})

    def log_message(self, format, *args):
        # Silence default terminal request spam
        return


def run_server(port: int = 8000):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, IoTRequestHandler)
    print("=" * 70)
    print("  SECURE IOT ARCHITECTURE - WEB GUI BACKEND RUNNING")
    print("=" * 70)
    print(f"[*] Access the Dashboard in your browser at: http://localhost:{port}")
    print(f"[*] Zero dependencies - Python standard library HTTP server")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    run_server(8000)
