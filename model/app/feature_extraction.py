# feature_extraction.py
import numpy as np

flows = {}

def calculate_flow_features(packet):
    if not hasattr(packet, 'ip') or not hasattr(packet, 'transport_layer'):
        return np.zeros(17)
    
    protocol = packet.transport_layer
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    src_port = int(getattr(packet[protocol], 'srcport', 0))
    dst_port = int(getattr(packet[protocol], 'dstport', 0))
    
    flow_id = (src_ip, dst_ip, src_port, dst_port, protocol)
    
    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": float(packet.sniff_time.timestamp()),
            "end_time": float(packet.sniff_time.timestamp()),
            "total_fwd_packets": 0, "total_bwd_packets": 0,
            "total_length_of_fwd_packets": 0, "total_length_of_bwd_packets": 0,
            "fwd_packet_lengths": [], "bwd_packet_lengths": [],
            "fwd_iat_times": [], "bwd_iat_times": [],
            "last_fwd_packet_time": None, "last_bwd_packet_time": None,
            "syn_flag_count": 0, "fin_flag_count": 0, "rst_flag_count": 0,
            "psh_flag_count": 0, "ack_flag_count": 0, "urg_flag_count": 0,
            "ece_flag_count": 0, "cwe_flag_count": 0,
            "fwd_psh_flags": 0, "bwd_psh_flags": 0,
            "fwd_urg_flags": 0, "bwd_urg_flags": 0,
            "fwd_header_length": int(getattr(packet[protocol], 'hdr_len', 0)), "bwd_header_length": 0,
            "init_win_bytes_forward": int(getattr(packet[protocol], 'window_size', 0)),
            "init_win_bytes_backward": None,
            "act_data_pkt_fwd": 0, "act_data_pkt_bwd": 0,
            "min_seg_size_forward": None, "down_up_ratio": 0,
            "average_packet_size": 0
        }

    flow = flows[flow_id]
    flow["end_time"] = float(packet.sniff_time.timestamp())

    is_fwd = src_ip < dst_ip  # Simple way to determine direction

    length = int(packet.length)
    
    if is_fwd:
        flow["total_fwd_packets"] += 1
        flow["total_length_of_fwd_packets"] += length
        flow["fwd_packet_lengths"].append(length)
        if flow["last_fwd_packet_time"] is not None:
            iat = float(packet.sniff_time.timestamp()) - flow["last_fwd_packet_time"]
            flow["fwd_iat_times"].append(iat)
        flow["last_fwd_packet_time"] = float(packet.sniff_time.timestamp())
        flow["act_data_pkt_fwd"] += 1 if length > 0 else 0
        if flow["min_seg_size_forward"] is None or length < flow["min_seg_size_forward"]:
            flow["min_seg_size_forward"] = length
        if hasattr(packet[protocol], 'flags'):
            flags = packet[protocol].flags
            if 'SYN' in flags: flow["syn_flag_count"] += 1
            if 'FIN' in flags: flow["fin_flag_count"] += 1
            if 'RST' in flags: flow["rst_flag_count"] += 1
            if 'PSH' in flags: 
                flow["psh_flag_count"] += 1
                flow["fwd_psh_flags"] += 1
            if 'ACK' in flags: flow["ack_flag_count"] += 1
            if 'URG' in flags: 
                flow["urg_flag_count"] += 1
                flow["fwd_urg_flags"] += 1
            if 'ECE' in flags: flow["ece_flag_count"] += 1
            if 'CWR' in flags: flow["cwe_flag_count"] += 1
    else:
        flow["total_bwd_packets"] += 1
        flow["total_length_of_bwd_packets"] += length
        flow["bwd_packet_lengths"].append(length)
        if flow["last_bwd_packet_time"] is not None:
            iat = float(packet.sniff_time.timestamp()) - flow["last_bwd_packet_time"]
            flow["bwd_iat_times"].append(iat)
        flow["last_bwd_packet_time"] = float(packet.sniff_time.timestamp())
        flow["act_data_pkt_bwd"] += 1 if length > 0 else 0
        if flow["init_win_bytes_backward"] is None:
            flow["init_win_bytes_backward"] = int(getattr(packet[protocol], 'window_size', 0))
        if hasattr(packet[protocol], 'flags'):
            flags = packet[protocol].flags
            if 'PSH' in flags: 
                flow["psh_flag_count"] += 1
                flow["bwd_psh_flags"] += 1
            if 'URG' in flags: 
                flow["urg_flag_count"] += 1
                flow["bwd_urg_flags"] += 1
            if 'SYN' in flags: flow["syn_flag_count"] += 1
            if 'FIN' in flags: flow["fin_flag_count"] += 1
            if 'RST' in flags: flow["rst_flag_count"] += 1
            if 'ACK' in flags: flow["ack_flag_count"] += 1
            if 'ECE' in flags: flow["ece_flag_count"] += 1
            if 'CWR' in flags: flow["cwe_flag_count"] += 1

    if flow["total_bwd_packets"] > 0:
        flow["down_up_ratio"] = flow["total_fwd_packets"] / flow["total_bwd_packets"]
    total_pkts = flow["total_fwd_packets"] + flow["total_bwd_packets"]
    if total_pkts > 0:
        flow["average_packet_size"] = (
            flow["total_length_of_fwd_packets"] + flow["total_length_of_bwd_packets"]
        ) / total_pkts

    all_pkt_lengths = flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]
    all_iat = flow["fwd_iat_times"] + flow["bwd_iat_times"]

    features = [
        flow["end_time"] - flow["start_time"],  # Duration
        total_pkts,  # Total packets
        flow["total_length_of_fwd_packets"] + flow["total_length_of_bwd_packets"],  # Total bytes
        total_pkts / max(flow["end_time"] - flow["start_time"], 1e-6),  # Pkts/s
        (flow["total_length_of_fwd_packets"] + flow["total_length_of_bwd_packets"]) / max(flow["end_time"] - flow["start_time"], 1e-6),  # Bytes/s
        flow["average_packet_size"],  # Avg pkt size
        np.std(all_pkt_lengths) if all_pkt_lengths else 0,  # Std pkt size
        min(all_pkt_lengths) if all_pkt_lengths else 0,  # Min pkt size
        max(all_pkt_lengths) if all_pkt_lengths else 0,  # Max pkt size
        np.mean(all_iat) if all_iat else 0,  # Avg IAT
        np.std(all_iat) if all_iat else 0,  # Std IAT
        flow["syn_flag_count"],  # SYN count
        flow["psh_flag_count"],  # PSH count
        flow["ack_flag_count"],  # ACK count
        1 if protocol == 'tcp' else 0,  # is_tcp
        1 if protocol == 'udp' else 0,  # is_udp
        1 if protocol == 'icmp' else 0   # is_icmp
    ]

    return np.array(features, dtype=np.float32)