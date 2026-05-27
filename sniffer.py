from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from logger import log_packet
from detector import detect_suspicious_traffic


def process_packet(packet):

    print("\n========== NEW PACKET ==========\n")

    # =========================
    # ETHERNET LAYER
    # =========================

    if packet.haslayer(Ether):

        print(f"SRC MAC : {packet[Ether].src}")
        print(f"DST MAC : {packet[Ether].dst}")

    # =========================
    # IP LAYER
    # =========================

    if packet.haslayer(IP):

        print(f"SRC IP  : {packet[IP].src}")
        print(f"DST IP  : {packet[IP].dst}")

    # =========================
    # TCP LAYER
    # =========================

    if packet.haslayer(TCP):

        tcp_layer = packet[TCP]

        print("\n[TCP PACKET]")

        print(f"SRC PORT : {tcp_layer.sport}")
        print(f"DST PORT : {tcp_layer.dport}")

        flags = tcp_layer.flags

        print(f"FLAGS    : {flags}")

        # =========================
        # TCP FLAG DETECTION
        # =========================

        if flags == "S":
            print("[INFO] SYN Packet Detected")

        elif flags == "SA":
            print("[INFO] SYN-ACK Packet Detected")

        elif flags == "F":
            print("[INFO] FIN Packet Detected")

        elif flags == "R":
            print("[INFO] RST Packet Detected")

        # =========================
        # SUSPICIOUS PORT DETECTION
        # =========================

        if detect_suspicious_traffic(tcp_layer.dport):

            print("\n[ALERT] Suspicious Port Activity Detected")

        # =========================
        # PACKET LOGGING
        # =========================

        if packet.haslayer(IP):

            log_data = (
                f"{packet[IP].src}:{tcp_layer.sport} "
                f"-> "
                f"{packet[IP].dst}:{tcp_layer.dport} "
                f"FLAGS={flags}"
            )

            log_packet(log_data)

    # =========================
    # UDP LAYER
    # =========================

    elif packet.haslayer(UDP):

        print("\n[UDP PACKET]")

        print(f"SRC PORT : {packet[UDP].sport}")
        print(f"DST PORT : {packet[UDP].dport}")

    # =========================
    # RAW PAYLOAD INSPECTION
    # =========================

    if packet.haslayer(Raw):

        payload = packet[Raw].load

        try:

            decoded_payload = payload.decode(errors="ignore")

            if "HTTP" in decoded_payload or "GET" in decoded_payload:

                print("\n[HTTP TRAFFIC DETECTED]\n")

                print(decoded_payload[:500])

        except:
            pass

    print("\n----------------------------------")


def start_sniffer():

    print("Starting packet sniffer...\n")

    sniff(filter="ip", prn=process_packet, store=False)