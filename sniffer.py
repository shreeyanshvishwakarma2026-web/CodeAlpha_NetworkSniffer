import scapy.all as scapy
from scapy.layers import http # Added to show more detail if you capture web traffic

def process_packet(packet):
    """
    Callback function to handle and parse each captured packet.
    """
    # We only care about IP-based traffic for this basic sniffer
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        # Mapping common protocol numbers to names for better readability
        proto_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)

        print(f"[+] IP {source_ip} --> {destination_ip} | Protocol: {proto_name}")

        # Check for HTTP or Raw data to show 'Payload' as requested by Task 1
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"    [!] Payload Data: {payload[:50]}...") # Show first 50 chars

def start_sniffer(interface=None):
    """
    Starts the sniffing process on a specific interface or all interfaces.
    """
    print(f"[*] Initializing Network Sniffer...")
    print(f"[*] Monitoring traffic... Press Ctrl+C to stop.")
    
    # store=False tells scapy not to keep every packet in RAM (prevents crashes)
    scapy.sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    try:
        # You can specify an interface here, e.g., start_sniffer("eth0")
        start_sniffer()
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer... Program exited by user.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")