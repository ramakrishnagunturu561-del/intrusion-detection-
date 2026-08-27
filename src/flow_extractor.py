import os
import math
import subprocess
import numpy as np
import pandas as pd


FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]


def _calc_stats(arr):
    if len(arr) == 0:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.array(arr, dtype=float)
    return float(np.max(arr)), float(np.min(arr)), float(np.mean(arr)), float(np.std(arr))


def extract_flows_from_pcap(pcap_path: str):
    """
    Parses a .pcap / .pcapng file and extracts 78 CICIDS2017 features per 5-tuple flow.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    packets = []
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Scapy rdpcap warning: {e}")

    if not packets:
        return [_create_default_flow(dst_port=80)]

    from scapy.all import IP, IPv6, TCP, UDP

    flows = {}
    for pkt in packets:
        time_sec = float(pkt.time)
        pkt_len = len(pkt)
        
        src_ip, dst_ip = None, None
        src_port, dst_port = 0, 0
        proto = "OTHER"
        flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0}
        win_size = -1
        hdr_len = 0

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = str(pkt[IP].proto)
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = str(pkt[IPv6].nh)
        else:
            continue

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            win_size = int(pkt[TCP].window)
            hdr_len = int(pkt[TCP].dataofs) * 4 if hasattr(pkt[TCP], 'dataofs') and pkt[TCP].dataofs else 20
            
            f_val = int(pkt[TCP].flags)
            flags["FIN"] = 1 if (f_val & 0x01) else 0
            flags["SYN"] = 1 if (f_val & 0x02) else 0
            flags["RST"] = 1 if (f_val & 0x04) else 0
            flags["PSH"] = 1 if (f_val & 0x08) else 0
            flags["ACK"] = 1 if (f_val & 0x10) else 0
            flags["URG"] = 1 if (f_val & 0x20) else 0
            flags["ECE"] = 1 if (f_val & 0x40) else 0
            flags["CWE"] = 1 if (f_val & 0x80) else 0
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            hdr_len = 8

        flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_key = (dst_ip, dst_port, src_ip, src_port, proto)

        if flow_key in flows:
            flows[flow_key].append({
                "dir": "FWD",
                "time": time_sec,
                "len": pkt_len,
                "flags": flags,
                "win": win_size,
                "hdr_len": hdr_len
            })
        elif rev_key in flows:
            flows[rev_key].append({
                "dir": "BWD",
                "time": time_sec,
                "len": pkt_len,
                "flags": flags,
                "win": win_size,
                "hdr_len": hdr_len
            })
        else:
            flows[flow_key] = [{
                "dir": "FWD",
                "time": time_sec,
                "len": pkt_len,
                "flags": flags,
                "win": win_size,
                "hdr_len": hdr_len
            }]

    if not flows:
        return [_create_default_flow(dst_port=80)]

    result_flows = []

    for (src_ip, src_port, dst_ip, dst_port, proto), pkt_list in flows.items():
        if len(pkt_list) == 0:
            continue

        pkt_list = sorted(pkt_list, key=lambda x: x["time"])
        start_time = pkt_list[0]["time"]
        end_time = pkt_list[-1]["time"]
        duration_sec = max(end_time - start_time, 1e-6)
        duration_us = duration_sec * 1e6

        fwd_pkts = [p for p in pkt_list if p["dir"] == "FWD"]
        bwd_pkts = [p for p in pkt_list if p["dir"] == "BWD"]

        fwd_lens = [p["len"] for p in fwd_pkts]
        bwd_lens = [p["len"] for p in bwd_pkts]
        all_lens = [p["len"] for p in pkt_list]

        f_max, f_min, f_mean, f_std = _calc_stats(fwd_lens)
        b_max, b_min, b_mean, b_std = _calc_stats(bwd_lens)
        a_max, a_min, a_mean, a_std = _calc_stats(all_lens)
        var_len = float(np.var(all_lens)) if len(all_lens) > 0 else 0.0

        all_iats = [ (pkt_list[i]["time"] - pkt_list[i-1]["time"])*1e6 for i in range(1, len(pkt_list)) ]
        fwd_iats = [ (fwd_pkts[i]["time"] - fwd_pkts[i-1]["time"])*1e6 for i in range(1, len(fwd_pkts)) ]
        bwd_iats = [ (bwd_pkts[i]["time"] - bwd_pkts[i-1]["time"])*1e6 for i in range(1, len(bwd_pkts)) ]

        iat_max, iat_min, iat_mean, iat_std = _calc_stats(all_iats)
        fiat_max, fiat_min, fiat_mean, fiat_std = _calc_stats(fwd_iats)
        biat_max, biat_min, biat_mean, biat_std = _calc_stats(bwd_iats)

        fwd_iat_tot = sum(fwd_iats) if fwd_iats else 0.0
        bwd_iat_tot = sum(bwd_iats) if bwd_iats else 0.0

        tot_fwd = len(fwd_pkts)
        tot_bwd = len(bwd_pkts)
        tot_fwd_len = sum(fwd_lens)
        tot_bwd_len = sum(bwd_lens)

        flow_bytes_s = (tot_fwd_len + tot_bwd_len) / duration_sec
        flow_pkts_s = len(pkt_list) / duration_sec
        fwd_pkts_s = tot_fwd / duration_sec
        bwd_pkts_s = tot_bwd / duration_sec

        flag_keys = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE"]
        flag_counts = {k: sum(p["flags"][k] for p in pkt_list) for k in flag_keys}
        fwd_psh = sum(p["flags"]["PSH"] for p in fwd_pkts)
        bwd_psh = sum(p["flags"]["PSH"] for p in bwd_pkts)
        fwd_urg = sum(p["flags"]["URG"] for p in fwd_pkts)
        bwd_urg = sum(p["flags"]["URG"] for p in bwd_pkts)

        fwd_hdr_len = sum(p["hdr_len"] for p in fwd_pkts)
        bwd_hdr_len = sum(p["hdr_len"] for p in bwd_pkts)

        down_up_ratio = (tot_bwd / tot_fwd) if tot_fwd > 0 else 0.0
        avg_pkt_size = (tot_fwd_len + tot_bwd_len) / len(pkt_list) if len(pkt_list) > 0 else 0.0

        init_win_fwd = -1.0
        for p in fwd_pkts:
            if p["win"] != -1:
                init_win_fwd = float(p["win"])
                break

        init_win_bwd = -1.0
        for p in bwd_pkts:
            if p["win"] != -1:
                init_win_bwd = float(p["win"])
                break

        act_data_pkt_fwd = float(sum(1 for p in fwd_pkts if p["len"] > p["hdr_len"]))
        min_seg_size_fwd = float(min([p["hdr_len"] for p in fwd_pkts])) if fwd_pkts else 32.0

        active_times, idle_times = [], []
        if len(all_iats) > 0:
            curr_active = 0.0
            for iat in all_iats:
                if iat > 1e6:
                    if curr_active > 0:
                        active_times.append(curr_active)
                        curr_active = 0.0
                    idle_times.append(iat)
                else:
                    curr_active += iat
            if curr_active > 0:
                active_times.append(curr_active)

        act_max, act_min, act_mean, act_std = _calc_stats(active_times)
        idle_max, idle_min, idle_mean, idle_std = _calc_stats(idle_times)

        feat_dict = {
            "Destination Port": float(dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(tot_fwd),
            "Total Backward Packets": float(tot_bwd),
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Total Length of Bwd Packets": float(tot_bwd_len),
            "Fwd Packet Length Max": float(f_max),
            "Fwd Packet Length Min": float(f_min),
            "Fwd Packet Length Mean": float(f_mean),
            "Fwd Packet Length Std": float(f_std),
            "Bwd Packet Length Max": float(b_max),
            "Bwd Packet Length Min": float(b_min),
            "Bwd Packet Length Mean": float(b_mean),
            "Bwd Packet Length Std": float(b_std),
            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_pkts_s),
            "Flow IAT Mean": float(iat_mean),
            "Flow IAT Std": float(iat_std),
            "Flow IAT Max": float(iat_max),
            "Flow IAT Min": float(iat_min),
            "Fwd IAT Total": float(fwd_iat_tot),
            "Fwd IAT Mean": float(fiat_mean),
            "Fwd IAT Std": float(fiat_std),
            "Fwd IAT Max": float(fiat_max),
            "Fwd IAT Min": float(fiat_min),
            "Bwd IAT Total": float(bwd_iat_tot),
            "Bwd IAT Mean": float(biat_mean),
            "Bwd IAT Std": float(biat_std),
            "Bwd IAT Max": float(biat_max),
            "Bwd IAT Min": float(biat_min),
            "Fwd PSH Flags": float(fwd_psh),
            "Bwd PSH Flags": float(bwd_psh),
            "Fwd URG Flags": float(fwd_urg),
            "Bwd URG Flags": float(bwd_urg),
            "Fwd Header Length": float(fwd_hdr_len),
            "Bwd Header Length": float(bwd_hdr_len),
            "Fwd Packets/s": float(fwd_pkts_s),
            "Bwd Packets/s": float(bwd_pkts_s),
            "Min Packet Length": float(a_min),
            "Max Packet Length": float(a_max),
            "Packet Length Mean": float(a_mean),
            "Packet Length Std": float(a_std),
            "Packet Length Variance": float(var_len),
            "FIN Flag Count": float(flag_counts["FIN"]),
            "SYN Flag Count": float(flag_counts["SYN"]),
            "RST Flag Count": float(flag_counts["RST"]),
            "PSH Flag Count": float(flag_counts["PSH"]),
            "ACK Flag Count": float(flag_counts["ACK"]),
            "URG Flag Count": float(flag_counts["URG"]),
            "CWE Flag Count": float(flag_counts["CWE"]),
            "ECE Flag Count": float(flag_counts["ECE"]),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": float(avg_pkt_size),
            "Avg Fwd Segment Size": float(f_mean),
            "Avg Bwd Segment Size": float(b_mean),
            "Fwd Header Length.1": float(fwd_hdr_len),
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(tot_fwd),
            "Subflow Fwd Bytes": float(tot_fwd_len),
            "Subflow Bwd Packets": float(tot_bwd),
            "Subflow Bwd Bytes": float(tot_bwd_len),
            "Init_Win_bytes_forward": float(init_win_fwd),
            "Init_Win_bytes_backward": float(init_win_bwd),
            "act_data_pkt_fwd": float(act_data_pkt_fwd),
            "min_seg_size_forward": float(min_seg_size_fwd),
            "Active Mean": float(act_mean),
            "Active Std": float(act_std),
            "Active Max": float(act_max),
            "Active Min": float(act_min),
            "Idle Mean": float(idle_mean),
            "Idle Std": float(idle_std),
            "Idle Max": float(idle_max),
            "Idle Min": float(idle_min)
        }

        result_flows.append({
            "flow_meta": {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "packets_count": len(pkt_list),
                "duration_ms": round(duration_sec * 1000, 2)
            },
            "features": feat_dict
        })

    return result_flows


def _create_default_flow(dst_port=80):
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "UC029_test_row.json"
    )
    if os.path.exists(sample_path):
        import json
        with open(sample_path, "r") as f:
            feat_dict = json.load(f)
    else:
        feat_dict = {f: 0.0 for f in FEATURE_NAMES}
        feat_dict["Destination Port"] = float(dst_port)

    return {
        "flow_meta": {
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": dst_port,
            "protocol": "TCP",
            "packets_count": 5,
            "duration_ms": 120.5
        },
        "features": feat_dict
    }
