from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        print(f"[{proto}] {ip_layer.src} --> {ip_layer.dst}")

        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load[:50]}")
            print("-" * 50)

print("Starting packet sniffer... Press CTRL+C to stop.")
sniff(prn=packet_callback, count=0, store=False)