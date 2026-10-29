"""
ThreatLens — Unit Tests for Real-Time Packet-to-Flow Feature Extraction
"""

import os
import sys
import time
import unittest
from scapy.all import IP, TCP, UDP, ICMP, rdpcap

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.flow_extractor import (
    NetworkPacket,
    FlowRecordState,
    RealtimeFlowAggregator,
    scapy_packet_to_network_packet
)
from ml.predict import ThreatPredictor


class TestFlowExtractor(unittest.TestCase):
    def setUp(self):
        self.aggregator = RealtimeFlowAggregator(flow_timeout_sec=0.5, max_active_flows=10)
        self.predictor = ThreatPredictor()

    def test_bidirectional_aggregation_and_features(self):
        t0 = time.time()
        # Forward packet: client to server
        p1 = NetworkPacket(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            payload_len=300,
            timestamp=t0,
            flags={"SYN": 1},
            window_size=29200
        )
        self.aggregator.process_packet(p1)

        # Backward packet: server to client
        p2 = NetworkPacket(
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            src_port=443,
            dst_port=54321,
            protocol="TCP",
            payload_len=1200,
            timestamp=t0 + 0.05,
            flags={"ACK": 1, "FIN": 1},
            window_size=28960
        )
        completed = self.aggregator.process_packet(p2)

        # Third packet closing connection
        p3 = NetworkPacket(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            payload_len=0,
            timestamp=t0 + 0.06,
            flags={"FIN": 1, "ACK": 1},
            window_size=29200
        )
        completed_final = self.aggregator.process_packet(p3)

        all_completed = completed + completed_final
        self.assertTrue(len(all_completed) >= 1)
        flow = all_completed[0]

        # Verify essential CIC-IDS2017 features are present
        required_features = [
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
            "ACK Flag Count"
        ]
        for feat in required_features:
            self.assertIn(feat, flow, f"Missing feature {feat}")

        self.assertEqual(flow["Destination Port"], 443)
        self.assertEqual(flow["Total Fwd Packets"], 2)
        self.assertEqual(flow["Total Backward Packets"], 1)

    def test_extracted_flow_schema_compatible_with_predictor(self):
        """Verifies that an extracted flow can be passed directly to the ML model."""
        if not self.predictor.is_ready():
            self.skipTest("Predictor model not trained yet")

        p = NetworkPacket(
            src_ip="10.1.1.2",
            dst_ip="10.1.1.5",
            src_port=49152,
            dst_port=80,
            protocol="TCP",
            payload_len=500,
            timestamp=time.time(),
            flags={"SYN": 1}
        )
        self.aggregator.process_packet(p)
        flushed = self.aggregator.flush_expired(force_all=True)
        self.assertEqual(len(flushed), 1)

        result = self.predictor.predict_flow(flushed[0])
        self.assertIn("prediction", result)
        self.assertIn("anomaly_score", result)
        self.assertIn("risk_level", result)
        self.assertTrue(0.0 <= result["anomaly_score"] <= 1.0)

    def test_bounded_memory_capacity(self):
        """Ensures active flows do not exceed max_active_flows."""
        small_aggregator = RealtimeFlowAggregator(flow_timeout_sec=10.0, max_active_flows=5)
        for i in range(15):
            pkt = NetworkPacket(
                src_ip="192.168.1.1",
                dst_ip=f"10.0.0.{i+1}",
                src_port=50000 + i,
                dst_port=80,
                protocol="TCP",
                payload_len=100
            )
            small_aggregator.process_packet(pkt)

        # Buffer must never exceed max_active_flows
        self.assertLessEqual(len(small_aggregator.active_flows), 5)

    def test_scapy_packet_to_network_packet_tcp(self):
        """Verifies conversion of Scapy TCP packet with flags and window size."""
        scapy_pkt = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(
            sport=44321, dport=443, flags="SA", window=64240
        )
        net_pkt = scapy_packet_to_network_packet(scapy_pkt)
        self.assertIsNotNone(net_pkt)
        self.assertEqual(net_pkt.src_ip, "192.168.1.50")
        self.assertEqual(net_pkt.dst_ip, "10.0.0.1")
        self.assertEqual(net_pkt.src_port, 44321)
        self.assertEqual(net_pkt.dst_port, 443)
        self.assertEqual(net_pkt.protocol, "TCP")
        self.assertEqual(net_pkt.window_size, 64240)
        self.assertTrue(net_pkt.flags.get("SYN"))
        self.assertTrue(net_pkt.flags.get("ACK"))
        self.assertFalse(net_pkt.flags.get("FIN"))

    def test_scapy_packet_to_network_packet_udp(self):
        """Verifies conversion of Scapy UDP packet."""
        scapy_pkt = IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000, dport=53)
        net_pkt = scapy_packet_to_network_packet(scapy_pkt)
        self.assertIsNotNone(net_pkt)
        self.assertEqual(net_pkt.protocol, "UDP")
        self.assertEqual(net_pkt.src_port, 53000)
        self.assertEqual(net_pkt.dst_port, 53)
        self.assertEqual(net_pkt.window_size, -1)

    def test_scapy_packet_to_network_packet_icmp(self):
        """Verifies conversion of Scapy ICMP packet."""
        scapy_pkt = IP(src="192.168.1.50", dst="192.168.1.1") / ICMP(type=8)
        net_pkt = scapy_packet_to_network_packet(scapy_pkt)
        self.assertIsNotNone(net_pkt)
        self.assertEqual(net_pkt.protocol, "ICMP")
        self.assertEqual(net_pkt.src_port, 0)
        self.assertEqual(net_pkt.dst_port, 8)
        self.assertEqual(net_pkt.window_size, -1)

    def test_pcap_fixture_flow_extraction(self):
        """Verifies processing packets from an actual PCAP fixture."""
        pcap_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_traffic.pcap")
        if not os.path.exists(pcap_path):
            self.skipTest(f"PCAP fixture not found at {pcap_path}")

        packets = rdpcap(pcap_path)
        self.assertGreater(len(packets), 0)

        agg = RealtimeFlowAggregator(flow_timeout_sec=0.1)
        all_flows = []
        for p in packets:
            net_p = scapy_packet_to_network_packet(p)
            if net_p:
                all_flows.extend(agg.process_packet(net_p))

        all_flows.extend(agg.flush_expired(force_all=True))
        self.assertGreater(len(all_flows), 0)
        for f in all_flows:
            self.assertIn("Destination Port", f)
            self.assertIn("Flow Duration", f)
            self.assertIn("Total Fwd Packets", f)
            self.assertIn("Total Backward Packets", f)

    def test_zero_duration_instantaneous_flow(self):
        """Ensures instantaneous single packet flow does not raise division-by-zero."""
        t = time.time()
        p = NetworkPacket(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            payload_len=100,
            timestamp=t
        )
        flow_state = FlowRecordState(("key",), p)
        features = flow_state.to_cicids_features()
        self.assertEqual(features["Flow Duration"], 0.0)
        self.assertEqual(features["Flow Bytes/s"], 0.0)
        self.assertEqual(features["Flow Packets/s"], 0.0)


if __name__ == "__main__":
    unittest.main()
