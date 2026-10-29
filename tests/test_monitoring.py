"""
ThreatLens — Unit Tests for Real-Time Monitoring Service, PCAP Replay, and Lifecycle Control
"""

import os
import sys
import time
import unittest
import queue

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.services.capture_service import NetworkCaptureService


class TestMonitoringService(unittest.TestCase):
    def setUp(self):
        self.service = NetworkCaptureService()
        if self.service.is_monitoring:
            self.service.stop_monitoring()

    def tearDown(self):
        if self.service.is_monitoring:
            self.service.stop_monitoring()

    def test_interface_discovery(self):
        res = self.service.get_available_interfaces()
        self.assertIn("interfaces", res)
        self.assertTrue(len(res["interfaces"]) > 0)
        self.assertIn("raw_socket_permission", res)
        self.assertIn("permission_note", res)

    def test_start_and_stop_lifecycle(self):
        # Start monitoring in synthetic benchmark mode (unprivileged safe)
        start_res = self.service.start_monitoring(
            interface="lo",
            mode="synthetic_test_stream",
            flow_timeout_sec=1.0
        )
        self.assertEqual(start_res["status"], "started")
        self.assertTrue(self.service.is_monitoring)

        # Preventing multiple simultaneous sessions
        second_start = self.service.start_monitoring(interface="lo")
        self.assertEqual(second_start["status"], "already_running")

        status = self.service.get_status()
        self.assertTrue(status["is_monitoring"])
        self.assertEqual(status["selected_interface"], "lo")

        # Stop monitoring
        stop_res = self.service.stop_monitoring()
        self.assertEqual(stop_res["status"], "stopped")
        self.assertFalse(self.service.is_monitoring)

    def test_bounded_recent_buffers(self):
        # Insert test flow directly to verify bounded capacity
        for i in range(250):
            test_flow = {
                "Destination Port": 80,
                "Flow Duration": 40000,
                "Total Fwd Packets": 2,
                "Total Backward Packets": 2,
                "Flow Bytes/s": 500.0,
                "Flow Packets/s": 40.0
            }
            self.service._score_and_record_flow(test_flow)

        self.assertLessEqual(len(self.service.recent_flows), 200)

    def test_permission_denial_explicit_error_never_silent(self):
        """
        When live raw capture is requested without root/BPF privileges,
        system must return explicit error and NEVER silently switch to synthetic.
        """
        # If running in environment without raw permissions
        perm = self.service.get_available_interfaces()
        if not perm["raw_socket_permission"]:
            res = self.service.start_monitoring(
                interface="lo0" if sys.platform == "darwin" else "eth0",
                mode="live_interface"
            )
            self.assertEqual(res["status"], "error")
            self.assertEqual(res["error"], "PERMISSION_DENIED")
            self.assertFalse(self.service.is_monitoring)
            # Must not be running synthetic mode secretly
            status = self.service.get_status()
            self.assertFalse(status["is_monitoring"])

    def test_pcap_replay_mode(self):
        """Verifies genuine PCAP replay mode."""
        pcap_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_traffic.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP fixture missing: {pcap_path}")

        res = self.service.start_monitoring(
            interface="pcap",
            mode="pcap_replay",
            flow_timeout_sec=0.1,
            pcap_path=pcap_path
        )
        self.assertEqual(res["status"], "started")
        time.sleep(0.3)
        self.service.stop_monitoring()
        self.assertGreater(self.service.total_packets, 0)

    def test_sse_delivery_of_events(self):
        """Verifies SSE queue subscription and event reception."""
        q = self.service.subscribe_events()
        try:
            self.service.inject_test_flow()
            # Dequeue event from subscriber
            event = q.get(timeout=2.0)
            self.assertIn("event", event)
            self.assertIn("data", event)
            self.assertEqual(event["event"], "flow")
        finally:
            self.service.unsubscribe_events(q)


if __name__ == "__main__":
    unittest.main()
