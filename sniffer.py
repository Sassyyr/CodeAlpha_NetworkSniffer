from scapy.all import sniff, IP
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] Source: {ip_layer.src} --> Destination: {ip_layer.dst} | Protocol: {ip_layer.proto}")
        print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
