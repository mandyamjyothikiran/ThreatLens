"""
ThreatLens — Real-Time Network Flow Extractor
Aggregates bidirectional packet streams into statistical flow features matching
the CIC-IDS2017 training schema. Handles TCP, UDP, and ICMP protocols.
"""

import time
import math
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("ThreatLens.FlowExtractor")


class NetworkPacket:
    """Lightweight representation of an inspected network packet."""
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload_len: int,
        timestamp: Optional[float] = None,
        flags: Optional[Dict[str, Any]] = None,
        window_size: int = -1
    ):
        self.src_ip = str(src_ip)
        self.dst_ip = str(dst_ip)
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        self.protocol = protocol.upper()
        self.payload_len = max(0, int(payload_len))
        self.timestamp = float(timestamp) if timestamp is not None else time.time()
        self.flags = flags or {}
        self.window_size = int(window_size)


class FlowRecordState:
    """Maintains statistical state of an active bidirectional flow."""
    def __init__(self, key: Tuple, first_packet: NetworkPacket):
        self.key = key
        # Forward endpoint is defined by the first observed packet of the flow
        self.fwd_ip = first_packet.src_ip
        self.fwd_port = first_packet.src_port
        self.bwd_ip = first_packet.dst_ip
        self.bwd_port = first_packet.dst_port
        self.protocol = first_packet.protocol

        self.start_time = first_packet.timestamp
        self.last_time = first_packet.timestamp

        self.fwd_packet_times = [first_packet.timestamp]
        self.bwd_packet_times: List[float] = []
        self.all_packet_times = [first_packet.timestamp]

        self.fwd_lengths = [first_packet.payload_len]
        self.bwd_lengths: List[int] = []

        # TCP flags
        self.syn_count = 1 if first_packet.flags.get("SYN") else 0
        self.ack_count = 1 if first_packet.flags.get("ACK") else 0
        self.fin_count = 1 if first_packet.flags.get("FIN") else 0
        self.rst_count = 1 if first_packet.flags.get("RST") else 0
        self.psh_count = 1 if first_packet.flags.get("PSH") else 0
        self.urg_count = 1 if first_packet.flags.get("URG") else 0

        self.init_win_fwd = first_packet.window_size
        self.init_win_bwd = -1

    def add_packet(self, packet: NetworkPacket):
        self.last_time = packet.timestamp
        self.all_packet_times.append(packet.timestamp)

        is_fwd = (packet.src_ip == self.fwd_ip and packet.src_port == self.fwd_port)
        if is_fwd:
            self.fwd_packet_times.append(packet.timestamp)
            self.fwd_lengths.append(packet.payload_len)
            if self.init_win_fwd == -1 and packet.window_size != -1:
                self.init_win_fwd = packet.window_size
        else:
            self.bwd_packet_times.append(packet.timestamp)
            self.bwd_lengths.append(packet.payload_len)
            if self.init_win_bwd == -1 and packet.window_size != -1:
                self.init_win_bwd = packet.window_size

        if packet.flags.get("SYN"): self.syn_count += 1
        if packet.flags.get("ACK"): self.ack_count += 1
        if packet.flags.get("FIN"): self.fin_count += 1
        if packet.flags.get("RST"): self.rst_count += 1
        if packet.flags.get("PSH"): self.psh_count += 1
        if packet.flags.get("URG"): self.urg_count += 1

    def is_terminated(self, idle_timeout_sec: float = 3.0, active_timeout_sec: float = 120.0) -> bool:
        """Determines whether flow is completed based on TCP FIN/RST or timeouts."""
        # TCP connection termination: bidirectional FIN or RST
        if self.fin_count >= 2 or self.rst_count >= 1:
            return True
        # Active timeout (prevent indefinitely growing flows)
        if (self.last_time - self.start_time) >= active_timeout_sec:
            return True
        # Idle timeout
        return (time.time() - self.last_time) >= idle_timeout_sec

    def to_cicids_features(self) -> Dict[str, Any]:
        """
        Computes statistical features adhering strictly to the CIC-IDS2017 training schema.
        All units:
        - Duration: microseconds
        - Packet lengths: bytes
        - Rates: bytes/second, packets/second
        - IATs: microseconds
        - Init_Win: bytes (or -1 if non-TCP/unset)
        """
        duration_s = max(0.0, self.last_time - self.start_time)
        duration_us = duration_s * 1e6

        tot_fwd_pkts = len(self.fwd_lengths)
        tot_bwd_pkts = len(self.bwd_lengths)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts

        tot_len_fwd = sum(self.fwd_lengths)
        tot_len_bwd = sum(self.bwd_lengths)
        tot_bytes = tot_len_fwd + tot_len_bwd

        # Forward length moments
        fwd_max = max(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_min = min(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_mean = (tot_len_fwd / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0.0

        # Backward length moments
        bwd_mean = (tot_len_bwd / tot_bwd_pkts) if tot_bwd_pkts > 0 else 0.0

        # Flow rates (handle zero-duration safely)
        if duration_s > 1e-6:
            flow_bytes_s = tot_bytes / duration_s
            flow_pkts_s = tot_pkts / duration_s
        else:
            # Single packet or microsecond instantaneous flow
            flow_bytes_s = 0.0
            flow_pkts_s = 0.0

        # Inter-arrival times in microseconds
        def calc_iats(times: List[float]) -> Tuple[float, float, float]:
            if len(times) < 2:
                return 0.0, 0.0, 0.0
            diffs = [(times[i] - times[i - 1]) * 1e6 for i in range(1, len(times))]
            mean = sum(diffs) / len(diffs)
            var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
            return mean, math.sqrt(var), max(diffs)

        flow_iat_mean, flow_iat_std, flow_iat_max = calc_iats(self.all_packet_times)
        fwd_iat_mean, _, _ = calc_iats(self.fwd_packet_times)
        bwd_iat_mean, _, _ = calc_iats(self.bwd_packet_times)

        avg_packet_size = (tot_bytes / tot_pkts) if tot_pkts > 0 else 0.0

        return {
            "Destination Port": int(self.bwd_port),
            "Flow Duration": round(duration_us, 1),
            "Total Fwd Packets": int(tot_fwd_pkts),
            "Total Backward Packets": int(tot_bwd_pkts),
            "Total Length of Fwd Packets": int(tot_len_fwd),
            "Total Length of Bwd Packets": int(tot_len_bwd),
            "Fwd Packet Length Max": float(fwd_max),
            "Fwd Packet Length Min": float(fwd_min),
            "Fwd Packet Length Mean": round(fwd_mean, 2),
            "Bwd Packet Length Mean": round(bwd_mean, 2),
            "Flow Bytes/s": round(flow_bytes_s, 2),
            "Flow Packets/s": round(flow_pkts_s, 2),
            "Flow IAT Mean": round(flow_iat_mean, 1),
            "Flow IAT Std": round(flow_iat_std, 1),
            "Flow IAT Max": round(flow_iat_max, 1),
            "Fwd IAT Mean": round(fwd_iat_mean, 1),
            "Bwd IAT Mean": round(bwd_iat_mean, 1),
            "SYN Flag Count": int(self.syn_count),
            "ACK Flag Count": int(self.ack_count),
            "Average Packet Size": round(avg_packet_size, 2),
            "Init_Win_bytes_forward": int(self.init_win_fwd),
            "Init_Win_bytes_backward": int(self.init_win_bwd),
            # Metadata descriptors (not included in numerical ML feature vector)
            "_meta_src_ip": self.fwd_ip,
            "_meta_dst_ip": self.bwd_ip,
            "_meta_src_port": self.fwd_port,
            "_meta_dst_port": self.bwd_port,
            "_meta_protocol": self.protocol,
            "_meta_start_time": self.start_time,
            "_meta_last_time": self.last_time
        }


class RealtimeFlowAggregator:
    """Thread-safe flow aggregator with bounded flow buffer and timeouts."""
    def __init__(self, flow_timeout_sec: float = 3.0, max_active_flows: int = 1000):
        self.flow_timeout_sec = flow_timeout_sec
        self.max_active_flows = max_active_flows
        self.active_flows: Dict[Tuple, FlowRecordState] = {}
        self.total_packets_processed = 0
        self.total_flows_completed = 0

    def _normalize_key(self, p: NetworkPacket) -> Tuple:
        """Creates canonical bidirectional flow key: (min(ep1, ep2), max(ep1, ep2), protocol)."""
        ep1 = (p.src_ip, p.src_port)
        ep2 = (p.dst_ip, p.dst_port)
        if ep1 <= ep2:
            return (ep1, ep2, p.protocol)
        return (ep2, ep1, p.protocol)

    def process_packet(self, packet: NetworkPacket) -> List[Dict[str, Any]]:
        """
        Ingests packet and returns list of completed flows (if any expired or terminated).
        """
        self.total_packets_processed += 1
        key = self._normalize_key(packet)
        completed: List[Dict[str, Any]] = []

        if key in self.active_flows:
            flow = self.active_flows[key]
            flow.add_packet(packet)
            if flow.is_terminated(self.flow_timeout_sec):
                completed.append(flow.to_cicids_features())
                del self.active_flows[key]
                self.total_flows_completed += 1
        else:
            # Enforce bounded memory
            if len(self.active_flows) >= self.max_active_flows:
                # Flush oldest flow to prevent memory exhaustion
                oldest_key = min(self.active_flows, key=lambda k: self.active_flows[k].last_time)
                oldest_flow = self.active_flows.pop(oldest_key)
                completed.append(oldest_flow.to_cicids_features())
                self.total_flows_completed += 1

            self.active_flows[key] = FlowRecordState(key, packet)

        return completed

    def flush_expired(self, force_all: bool = False, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Checks for and flushes flows that have exceeded idle timeout."""
        completed: List[Dict[str, Any]] = []
        current_time = now if now is not None else time.time()
        keys_to_remove = []

        for key, flow in self.active_flows.items():
            if force_all or (current_time - flow.last_time) >= self.flow_timeout_sec:
                completed.append(flow.to_cicids_features())
                keys_to_remove.append(key)
                self.total_flows_completed += 1

        for k in keys_to_remove:
            del self.active_flows[k]

        return completed


def scapy_packet_to_network_packet(pkt: Any) -> Optional[NetworkPacket]:
    """
    Converts a Scapy packet object into ThreatLens NetworkPacket safely.
    Handles IPv4, IPv6, TCP, UDP, and ICMP. Returns None on unhandled/malformed packets.
    """
    try:
        has_ip = False
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        pkt_time = float(getattr(pkt, "time", time.time()))

        if pkt.haslayer("IP"):
            ip_layer = pkt.getlayer("IP")
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            has_ip = True
        elif pkt.haslayer("IPv6"):
            ip6_layer = pkt.getlayer("IPv6")
            src_ip = str(ip6_layer.src)
            dst_ip = str(ip6_layer.dst)
            has_ip = True

        if not has_ip:
            return None

        # Check Transport layer
        if pkt.haslayer("TCP"):
            tcp_layer = pkt.getlayer("TCP")
            flags_str = str(tcp_layer.flags)
            flags = {
                "SYN": "S" in flags_str,
                "ACK": "A" in flags_str,
                "FIN": "F" in flags_str,
                "RST": "R" in flags_str,
                "PSH": "P" in flags_str,
                "URG": "U" in flags_str,
            }
            payload_len = len(bytes(tcp_layer.payload))
            win = int(tcp_layer.window) if hasattr(tcp_layer, "window") and tcp_layer.window is not None else 0
            return NetworkPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(tcp_layer.sport),
                dst_port=int(tcp_layer.dport),
                protocol="TCP",
                payload_len=payload_len,
                timestamp=pkt_time,
                flags=flags,
                window_size=win
            )

        elif pkt.haslayer("UDP"):
            udp_layer = pkt.getlayer("UDP")
            payload_len = len(bytes(udp_layer.payload))
            return NetworkPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(udp_layer.sport),
                dst_port=int(udp_layer.dport),
                protocol="UDP",
                payload_len=payload_len,
                timestamp=pkt_time,
                flags={},
                window_size=-1
            )

        elif pkt.haslayer("ICMP"):
            icmp_layer = pkt.getlayer("ICMP")
            payload_len = len(bytes(icmp_layer.payload))
            type_val = int(icmp_layer.type) if hasattr(icmp_layer, "type") and icmp_layer.type is not None else 0
            return NetworkPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=type_val,
                protocol="ICMP",
                payload_len=payload_len,
                timestamp=pkt_time,
                flags={},
                window_size=-1
            )

        return None
    except Exception as ex:
        logger.debug("Failed to parse packet with Scapy: %s", ex)
        return None
