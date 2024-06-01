# Import the necessary Scapy library
import scapy.all as scapy

def packet_analyzer(packet):
    """
    This function is called for each packet that is captured.
    It extracts the source IP, destination IP, and protocol of the packet.
    If the packet contains TCP or UDP layers, it attempts to decode and print the payload.

    :param packet: Packet object to be analyzed
    """
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"[+] Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

        # If the packet has a TCP layer, decode and print the payload
        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"[+] TCP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                print("[!] Unable to decode TCP payload.")

        # If the packet has a UDP layer, decode and print the payload
        elif packet.haslayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"[+] UDP Payload: {decoded_payload}")
            except (IndexError, UnicodeDecodeError):
                print("[!] Unable to decode UDP payload.")

def start_packet_capture():
    """
    Start capturing packets using Scapy's sniff function.
    The 'prn' parameter is set to the packet_analyzer function, which will be called for each packet.
    The 'store' parameter is set to False to avoid storing packets in memory.
    """
    scapy.sniff(store=False, prn=packet_analyzer)

# Start capturing packets
start_packet_capture()