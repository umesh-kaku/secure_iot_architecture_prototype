"""
Direct programmatic test of server API handlers without needing network sockets.
"""
import io
import json
import unittest
from server import IoTRequestHandler, STATE


class DummySocket:
    def __init__(self, request_bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args):
        if "r" in mode:
            return self.rfile
        return self.wfile


class TestServerAPI(unittest.TestCase):
    def test_get_state(self):
        state = STATE.get_state_summary()
        self.assertIn("devices", state)
        self.assertIn("resources", state)
        self.assertIn("revoked_devices", state)
        self.assertIn("audit_logs", state)
        self.assertGreater(len(state["devices"]), 0)

    def test_auth_simulation_and_access(self):
        # 1. Authenticate dev-sensor-01
        sensor = STATE.devices["dev-sensor-01"]
        ok, tok, msg, _ = STATE.gateway.authenticate_device(sensor)
        self.assertTrue(ok)
        sensor.store_token(tok)

        # 2. Access telemetry
        req = sensor.create_access_request("res:telemetry:sensor_data", "write")
        dec, _, _ = STATE.gateway.process_access_request(req)
        self.assertTrue(dec.allowed)

        # 3. Denied access (Sensor -> Power Grid)
        req_bad = sensor.create_access_request("res:critical:power_grid_switch", "execute")
        dec_bad, _, _ = STATE.gateway.process_access_request(req_bad)
        self.assertFalse(dec_bad.allowed)

    def test_revocation_lockout(self):
        admin = STATE.devices["dev-admin-01"]
        STATE.gateway.authenticate_device(admin)
        STATE.gateway.revoke_device(admin.device_id, "Testing revocation")
        
        req = admin.create_access_request("res:critical:power_grid_switch", "execute")
        dec, _, _ = STATE.gateway.process_access_request(req)
        self.assertFalse(dec.allowed)


if __name__ == "__main__":
    unittest.main()
