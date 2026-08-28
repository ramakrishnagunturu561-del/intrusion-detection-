from src.flow_extractor import extract_flows_from_pcap
from src.prediction import detect_intrusion

PCAP = r"C:\Users\bapi0\Downloads\intrusion-detection-\test_live.pcapng"

FEATURES = [
    "Init_Win_bytes_forward",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Avg Bwd Segment Size",
    "Subflow Fwd Bytes",
]

flows = extract_flows_from_pcap(PCAP)

print()
print("=" * 150)
print("LIVE FLOW PREDICTION TEST")
print("=" * 150)
print(f"Total flows: {len(flows)}")
print()

for i, flow in enumerate(flows, start=1):

    features = flow["features"]
    result = detect_intrusion(features)

    print(f"FLOW {i}")
    print("-" * 150)

    print("Source      :", flow["flow_meta"]["src_ip"])
    print("Destination :", flow["flow_meta"]["dst_ip"])
    print("Protocol    :", flow["flow_meta"]["protocol"])

    print("Classical   :", result["classical_prediction"])
    print("Quantum     :", result["quantum_prediction"])
    print("Final       :", result["final_prediction"])
    print("Risk        :", result["risk_level"])

    print("6 Quantum features:")

    for feature in FEATURES:
        print(
            f"  {feature}: "
            f"{features[feature]}"
        )

    print()

print("=" * 150)
print("TEST COMPLETE")
print("=" * 150)
