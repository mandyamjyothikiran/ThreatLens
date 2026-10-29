"""
ThreatLens — Real-Time Network Packet Capture & Monitoring Service
Captures authorized traffic via Scapy / raw sockets, aggregates flows,
feeds ML inference engine, and broadcasts alerts in real time via Server-Sent Events.
"""

import os
import sys
import time
import socket
import threading
import queue
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from ml.flow_extractor import NetworkPacket, RealtimeFlowAggregator, scapy_packet_to_network_packet
from backend.services.model_service import ModelService

logger = logging.getLogger("ThreatLens.CaptureService")


class NetworkCaptureService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NetworkCaptureService, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, "initialized", False):
            return

        self.model_service = ModelService()
        self.aggregator = RealtimeFlowAggregator(flow_timeout_sec=3.0, max_active_flows=1000)

        # Threading and control
        self.is_monitoring = False
        self.capture_thread: Optional[threading.Thread] = None
        self.flush_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.scapy_sniffer = None

        # Telemetry
        self.selected_interface: Optional[str] = None
        self.capture_mode = "idle"  # "live_interface" | "pcap_replay" | "synthetic_test_stream"
        self.start_timestamp: Optional[str] = None
        self.total_packets = 0
        self.total_flows = 0
        self.total_anomalies = 0
        self.malformed_packets_dropped = 0
        self.last_error: Optional[str] = None

        # Bounded buffers for dashboard
        self.recent_flows: List[Dict[str, Any]] = []   # max 200
        self.recent_alerts: List[Dict[str, Any]] = []  # max 200

        # SSE subscriber queues
        self.subscribers: List[queue.Queue] = []

        self.initialized = True
        logger.info("NetworkCaptureService initialized.")

    def get_available_interfaces(self) -> Dict[str, Any]:
        """Discovers authorized local network interfaces safely."""
        interfaces_map = {}

        # 1. Query Scapy interfaces
        try:
            from scapy.all import get_if_list, conf
            scapy_ifaces = get_if_list()
            for idx, iface in enumerate(scapy_ifaces):
                name = str(iface)
                is_loopback = (name.lower() in ("lo", "lo0") or "loopback" in name.lower())
                interfaces_map[name] = {
                    "id": name,
                    "name": name,
                    "index": idx + 1,
                    "is_loopback": is_loopback,
                    "description": "Loopback Interface" if is_loopback else f"Network Interface {name}",
                    "supported": True
                }
        except Exception as ex:
            logger.debug("Scapy get_if_list() query failed: %s", ex)

        # 2. Query OS socket interfaces
        try:
            if hasattr(socket, "if_nameindex"):
                for idx, name in socket.if_nameindex():
                    if name not in interfaces_map:
                        is_loopback = (name.lower() in ("lo", "lo0") or "loopback" in name.lower())
                        interfaces_map[name] = {
                            "id": name,
                            "name": name,
                            "index": idx,
                            "is_loopback": is_loopback,
                            "description": "Loopback Virtual Device" if is_loopback else f"Physical/Virtual Interface {name}",
                            "supported": True
                        }
        except Exception as ex:
            logger.debug("socket.if_nameindex() unavailable: %s", ex)

        if not interfaces_map:
            # Fallback descriptors
            interfaces_map["lo"] = {"id": "lo", "name": "lo", "index": 1, "is_loopback": True, "description": "Local Loopback Device", "supported": True}
            interfaces_map["eth0"] = {"id": "eth0", "name": "eth0", "index": 2, "is_loopback": False, "description": "Primary Ethernet Interface", "supported": True}

        interfaces = list(interfaces_map.values())
        # Sort so loopback appears after primary interfaces or by index
        interfaces.sort(key=lambda x: (x["is_loopback"], x["index"]))

        # Check raw socket / BPF capture permissions
        has_raw_cap = False
        permission_details = ""
        # Check BPF on macOS
        if sys.platform == "darwin":
            bpf_accessible = False
            for i in range(10):
                p = f"/dev/bpf{i}"
                if os.path.exists(p) and os.access(p, os.R_OK):
                    bpf_accessible = True
                    break
            has_raw_cap = bpf_accessible
            if not has_raw_cap:
                permission_details = (
                    "macOS: Raw packet capture requires read access to /dev/bpf*. "
                    "Run ThreatLens with sudo or grant group access: sudo chmod 640 /dev/bpf* and sudo chgrp admin /dev/bpf*. "
                    "PCAP replay and synthetic stream are accessible without elevated privileges."
                )
            else:
                permission_details = "macOS BPF packet capture permissions verified."
        else:
            # Linux / Unix
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.close()
                has_raw_cap = True
                permission_details = "Raw socket capture capabilities verified."
            except PermissionError:
                has_raw_cap = False
                permission_details = (
                    "Linux: Packet capture requires CAP_NET_RAW capability or root privileges. "
                    "Run with sudo or set capability: sudo setcap cap_net_raw,cap_net_admin=eip <python_path>. "
                    "PCAP replay and synthetic stream are accessible without elevated privileges."
                )
            except Exception as e:
                has_raw_cap = False
                permission_details = f"Raw socket unavailable ({e}). PCAP replay and synthetic benchmark available."

        return {
            "interfaces": interfaces,
            "raw_socket_permission": has_raw_cap,
            "permission_note": permission_details
        }

    def start_monitoring(
        self,
        interface: str = "lo",
        mode: str = "synthetic_test_stream",
        flow_timeout_sec: float = 3.0,
        threshold_override: Optional[float] = None,
        pcap_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Starts real-time background capture and flow processing.
        NEVER silently switches from live interface capture to synthetic.
        Returns explicit error if capture cannot start.
        """
        with self.lock:
            if self.is_monitoring:
                return {
                    "status": "already_running",
                    "message": f"Capture session already active on interface {self.selected_interface}",
                    "current_status": self.get_status()
                }

            self.selected_interface = interface
            self.capture_mode = mode
            self.start_timestamp = datetime.now(timezone.utc).isoformat() + "Z"
            self.stop_event.clear()
            self.last_error = None

            self.aggregator = RealtimeFlowAggregator(
                flow_timeout_sec=flow_timeout_sec,
                max_active_flows=1000
            )

            # Test permission immediately if live capture requested
            if mode == "live_interface":
                # Verify permissions
                perm_info = self.get_available_interfaces()
                if not perm_info["raw_socket_permission"]:
                    self.is_monitoring = False
                    self.last_error = (
                        f"Permission Denied: Cannot capture raw packets on interface '{interface}'. "
                        f"{perm_info['permission_note']}"
                    )
                    logger.error("Live capture refused: %s", self.last_error)
                    return {
                        "status": "error",
                        "error": "PERMISSION_DENIED",
                        "message": self.last_error,
                        "interface": interface,
                        "mode": mode
                    }

                # Start genuine Scapy capture worker
                self.is_monitoring = True
                self.capture_thread = threading.Thread(
                    target=self._live_scapy_worker,
                    args=(interface, threshold_override),
                    daemon=True
                )
            elif mode == "pcap_replay":
                # Validate PCAP path
                target_pcap = pcap_path or "data/sample_traffic.pcap"
                if not os.path.exists(target_pcap):
                    self.is_monitoring = False
                    self.last_error = f"PCAP fixture not found at {target_pcap}"
                    return {
                        "status": "error",
                        "error": "FILE_NOT_FOUND",
                        "message": self.last_error,
                        "mode": mode
                    }

                self.is_monitoring = True
                self.capture_thread = threading.Thread(
                    target=self._pcap_replay_worker,
                    args=(target_pcap, threshold_override),
                    daemon=True
                )
            else:
                # Explicit synthetic benchmark generator
                self.is_monitoring = True
                self.capture_thread = threading.Thread(
                    target=self._synthetic_generator_worker,
                    args=(interface, threshold_override),
                    daemon=True
                )

            # Flush worker to expire idle flows
            self.flush_thread = threading.Thread(
                target=self._flow_flush_worker,
                args=(threshold_override,),
                daemon=True
            )

            self.capture_thread.start()
            self.flush_thread.start()

            logger.info("Monitoring started on %s [Mode: %s]", interface, mode)
            return {
                "status": "started",
                "interface": interface,
                "mode": mode,
                "started_at": self.start_timestamp,
                "flow_timeout_sec": flow_timeout_sec
            }

    def stop_monitoring(self) -> Dict[str, Any]:
        """Stops active monitoring and flushes all pending flows."""
        cap_t = None
        flush_t = None
        with self.lock:
            if not self.is_monitoring:
                return {"status": "not_running", "message": "No active monitoring session to stop."}

            self.is_monitoring = False
            self.stop_event.set()
            cap_t = self.capture_thread
            flush_t = self.flush_thread

            if self.scapy_sniffer is not None:
                try:
                    self.scapy_sniffer.stop()
                except Exception as ex:
                    logger.debug("Error stopping Scapy sniffer: %s", ex)
                self.scapy_sniffer = None

        # Join outside lock
        if cap_t and cap_t.is_alive():
            cap_t.join(timeout=1.0)
        if flush_t and flush_t.is_alive():
            flush_t.join(timeout=1.0)

        # Flush remaining active flows
        remaining = self.aggregator.flush_expired(force_all=True)
        for flow in remaining:
            self._score_and_record_flow(flow)

        duration = 0.0
        if self.start_timestamp:
            try:
                start_dt = datetime.fromisoformat(self.start_timestamp.replace("Z", "+00:00"))
                duration = (datetime.now(timezone.utc) - start_dt).total_seconds()
            except Exception:
                pass

        logger.info("Monitoring stopped on %s after %.1fs", self.selected_interface, duration)
        return {
            "status": "stopped",
            "interface": self.selected_interface,
            "duration_seconds": round(duration, 1),
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "total_anomalies": self.total_anomalies
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational telemetry and counters."""
        duration = 0
        if self.is_monitoring and self.start_timestamp:
            try:
                start_dt = datetime.fromisoformat(self.start_timestamp.replace("Z", "+00:00"))
                duration = int((datetime.now(timezone.utc) - start_dt).total_seconds())
            except Exception:
                duration = 0

        return {
            "is_monitoring": self.is_monitoring,
            "selected_interface": self.selected_interface,
            "capture_mode": self.capture_mode,
            "started_at": self.start_timestamp,
            "uptime_seconds": duration,
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "total_anomalies": self.total_anomalies,
            "malformed_packets_dropped": self.malformed_packets_dropped,
            "last_error": self.last_error,
            "active_flows_in_memory": len(self.aggregator.active_flows),
            "model_ready": self.model_service.predictor.is_ready(),
            "subscriber_count": len(self.subscribers)
        }

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return self.recent_flows[-limit:][::-1]

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            return self.recent_alerts[-limit:][::-1]

    def subscribe_events(self) -> queue.Queue:
        """Returns a thread-safe Queue for Server-Sent Events."""
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe_events(self, q: queue.Queue):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def _broadcast_event(self, event_type: str, data: Dict[str, Any]):
        """Dispatches event to all active SSE subscribers."""
        dead_queues = []
        for q in self.subscribers:
            try:
                q.put_nowait({"event": event_type, "data": data})
            except queue.Full:
                dead_queues.append(q)
        for dq in dead_queues:
            self.unsubscribe_events(dq)

    def _score_and_record_flow(self, flow_dict: Dict[str, Any], threshold_override: Optional[float] = None):
        """Feeds completed flow into ThreatLens ML Predictor and updates buffers."""
        try:
            pred_res = self.model_service.predict(flow_dict, threshold_override=threshold_override)
        except Exception as ex:
            logger.error("Failed to score live flow: %s", ex)
            return

        self.total_flows += 1
        flow_id = f"LIVE-{self.total_flows:05d}"
        now_iso = datetime.now(timezone.utc).isoformat() + "Z"

        record = {
            "id": flow_id,
            "timestamp": now_iso,
            "dest_port": int(flow_dict.get("Destination Port", 80)),
            "protocol": flow_dict.get("_meta_protocol", "TCP"),
            "src_ip": flow_dict.get("_meta_src_ip", "127.0.0.1"),
            "dst_ip": flow_dict.get("_meta_dst_ip", "127.0.0.1"),
            "duration_us": float(flow_dict.get("Flow Duration", 0)),
            "total_fwd_pkts": int(flow_dict.get("Total Fwd Packets", 1)),
            "total_bwd_pkts": int(flow_dict.get("Total Backward Packets", 0)),
            "flow_bytes_per_sec": float(flow_dict.get("Flow Bytes/s", 0)),
            "flow_pkts_per_sec": float(flow_dict.get("Flow Packets/s", 0)),
            "anomaly_score": pred_res["anomaly_score"],
            "decision_function": pred_res.get("decision_function", 0.0),
            "calibrated_threshold": pred_res["calibrated_threshold"],
            "is_anomaly": pred_res["is_anomaly"],
            "risk_level": pred_res["risk_level"],
            "prediction": pred_res["prediction"],
            "top_features": pred_res.get("top_contributing_features", []),
            "is_test_data": self.capture_mode == "synthetic_test_stream",
            "capture_mode": self.capture_mode,
            "features": flow_dict
        }

        with self.lock:
            self.recent_flows.append(record)
            if len(self.recent_flows) > 200:
                self.recent_flows.pop(0)

        # Broadcast live flow event
        self._broadcast_event("flow", record)

        # If flagged anomalous, create model-derived alert
        if pred_res["is_anomaly"]:
            self.total_anomalies += 1
            alert = {
                "alert_id": f"L-ALT-{self.total_anomalies:04d}",
                "flow_id": flow_id,
                "timestamp": now_iso,
                "dest_port": record["dest_port"],
                "protocol": record["protocol"],
                "src_ip": record["src_ip"],
                "dst_ip": record["dst_ip"],
                "anomaly_score": pred_res["anomaly_score"],
                "decision_function": pred_res.get("decision_function", 0.0),
                "risk_severity": pred_res["risk_level"],
                "prediction_category": pred_res["prediction"],
                "finding_type": "Model-Generated Anomaly",
                "investigation_status": "Analyst Review Required",
                "trigger_category": "Zero-Day Behavioral Divergence" if pred_res["anomaly_score"] > 0.8 else "Statistical Outlier",
                "top_contributing_features": pred_res.get("top_contributing_features", []),
                "capture_mode": self.capture_mode,
                "is_test_data": self.capture_mode == "synthetic_test_stream",
                "academic_disclaimer": "Live detection alert generated by Isolation Forest. Indicates statistical departure from normal baseline."
            }

            with self.lock:
                self.recent_alerts.append(alert)
                if len(self.recent_alerts) > 200:
                    self.recent_alerts.pop(0)

            self._broadcast_event("alert", alert)

    def _flow_flush_worker(self, threshold_override: Optional[float] = None):
        """Periodically flushes idle flows that timed out."""
        while not self.stop_event.is_set():
            if self.stop_event.wait(1.0):
                break
            expired = self.aggregator.flush_expired()
            for f in expired:
                self._score_and_record_flow(f, threshold_override)

    def _live_scapy_worker(self, interface: str, threshold_override: Optional[float] = None):
        """
        Genuine live packet capture using Scapy sniff loop.
        Never silently switches to synthetic data if permission fails.
        """
        logger.info("Opening Scapy live capture on interface: %s", interface)
        try:
            from scapy.all import sniff

            def packet_handler(scapy_pkt):
                if self.stop_event.is_set():
                    return
                try:
                    net_pkt = scapy_packet_to_network_packet(scapy_pkt)
                    if net_pkt is not None:
                        self.total_packets += 1
                        completed = self.aggregator.process_packet(net_pkt)
                        for f in completed:
                            self._score_and_record_flow(f, threshold_override)
                except Exception as ex:
                    self.malformed_packets_dropped += 1
                    logger.debug("Malformed packet dropped: %s", ex)

            sniff(
                iface=interface,
                prn=packet_handler,
                stop_filter=lambda p: self.stop_event.is_set(),
                store=False
            )
        except Exception as ex:
            logger.error("Scapy capture failed on interface %s: %s", interface, ex)
            self.last_error = f"Capture terminated unexpectedly: {str(ex)}"
            self.is_monitoring = False

    def _pcap_replay_worker(self, pcap_path: str, threshold_override: Optional[float] = None):
        """
        Replays packets from a genuine PCAP capture file.
        Passes packets through the same parsing, flow aggregation, and ML inference.
        """
        logger.info("Replaying PCAP file: %s", pcap_path)
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_path)
            logger.info("Read %d packets from %s", len(packets), pcap_path)

            for scapy_pkt in packets:
                if self.stop_event.is_set():
                    break
                net_pkt = scapy_packet_to_network_packet(scapy_pkt)
                if net_pkt is not None:
                    self.total_packets += 1
                    completed = self.aggregator.process_packet(net_pkt)
                    for f in completed:
                        self._score_and_record_flow(f, threshold_override)
                # Small inter-packet pacing for live dashboard visualization
                if self.stop_event.wait(0.02):
                    break

            # Flush completed flows after PCAP replay
            remaining = self.aggregator.flush_expired(force_all=True)
            for f in remaining:
                self._score_and_record_flow(f, threshold_override)

        except Exception as ex:
            logger.error("Error reading PCAP %s: %s", pcap_path, ex)
            self.last_error = f"PCAP replay error: {str(ex)}"
            self.is_monitoring = False

    def _synthetic_generator_worker(self, interface: str, threshold_override: Optional[float] = None):
        """
        Generates realistic network flow streams labeled explicitly as TEST DATA.
        Used for verification when live interfaces are unavailable or unauthorized.
        """
        logger.info("Synthetic benchmark flow generator active on %s (MODE: SYNTHETIC DEMO)", interface)
        step = 0

        scenarios = [
            {"dst_port": 443, "proto": "TCP", "pkts_fwd": 8, "pkts_bwd": 12, "len_fwd": 650, "len_bwd": 4200, "duration": 0.45, "syn": 1, "ack": 1},
            {"dst_port": 53, "proto": "UDP", "pkts_fwd": 2, "pkts_bwd": 2, "len_fwd": 68, "len_bwd": 240, "duration": 0.02, "syn": 0, "ack": 0},
            {"dst_port": 8080, "proto": "TCP", "pkts_fwd": 5, "pkts_bwd": 6, "len_fwd": 380, "len_bwd": 1240, "duration": 0.18, "syn": 1, "ack": 1},
            # Reconnaissance PortScan
            {"dst_port": 445, "proto": "TCP", "pkts_fwd": 1, "pkts_bwd": 1, "len_fwd": 0, "len_bwd": 0, "duration": 0.0004, "syn": 1, "ack": 0},
            {"dst_port": 443, "proto": "TCP", "pkts_fwd": 14, "pkts_bwd": 18, "len_fwd": 890, "len_bwd": 6200, "duration": 0.62, "syn": 1, "ack": 1},
            # Infiltration pattern
            {"dst_port": 4444, "proto": "TCP", "pkts_fwd": 28, "pkts_bwd": 24, "len_fwd": 4820, "len_bwd": 4100, "duration": 2.85, "syn": 1, "ack": 1}
        ]

        while not self.stop_event.is_set():
            scenario = scenarios[step % len(scenarios)]
            step += 1
            now = time.time()
            src_p = 49152 + (step % 1000)

            p1 = NetworkPacket(
                src_ip="192.168.1.105",
                dst_ip="10.0.0.1",
                src_port=src_p,
                dst_port=scenario["dst_port"],
                protocol=scenario["proto"],
                payload_len=scenario["len_fwd"] // max(1, scenario["pkts_fwd"]),
                timestamp=now,
                flags={"SYN": bool(scenario["syn"])},
                window_size=29200
            )
            self.total_packets += scenario["pkts_fwd"]
            completed = self.aggregator.process_packet(p1)
            for f in completed:
                self._score_and_record_flow(f, threshold_override)

            if self.stop_event.wait(0.05):
                break

            if scenario["pkts_bwd"] > 0:
                p2 = NetworkPacket(
                    src_ip="10.0.0.1",
                    dst_ip="192.168.1.105",
                    src_port=scenario["dst_port"],
                    dst_port=src_p,
                    protocol=scenario["proto"],
                    payload_len=scenario["len_bwd"] // scenario["pkts_bwd"],
                    timestamp=now + scenario["duration"],
                    flags={"ACK": bool(scenario["ack"])},
                    window_size=28960
                )
                self.total_packets += scenario["pkts_bwd"]
                completed = self.aggregator.process_packet(p2)
                for f in completed:
                    self._score_and_record_flow(f, threshold_override)

            if self.stop_event.wait(1.5):
                break

    def inject_test_flow(self, flow_dict: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        On-demand injection of a test packet or flow for pipeline testing.
        Allows instant verification of SSE and ML scoring without interface permissions.
        """
        now = time.time()
        p = NetworkPacket(
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            src_port=54321,
            dst_port=8080,
            protocol="TCP",
            payload_len=450,
            timestamp=now,
            flags={"SYN": True, "ACK": True},
            window_size=64240
        )
        self.total_packets += 1
        completed = self.aggregator.process_packet(p)
        # Flush the single flow immediately for instant feedback
        forced = self.aggregator.flush_expired(force_all=True)
        completed.extend(forced)

        scored = []
        for f in completed:
            self._score_and_record_flow(f)
            scored.append(f)

        return {
            "status": "injected",
            "packets_processed": 1,
            "flows_generated": len(scored),
            "message": "Authorized test packet processed through flow extractor and ML engine."
        }
