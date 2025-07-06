import time
import scapy
from scapy.all import sniff, IP, TCP, UDP 

ENCRYPTED_PORTS = {443, 853, 993 , 995, 8443} # https, dns-over-tls, imap-over-tls, pop3s, https-alt

## ports for potential use later 
''' WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
    }
'''


# global variabels
packet_count = 0
tcp_count = 0
udp_count = 0
start_time = time.time()
unique_ips = set()

def packet_callback(packet):
    global packet_count, tcp_count, udp_count, start_time
    
    packet_count += 1
    if IP in packet:
        
        unique_ips.add(ip_layer.src) 
        unique_ips.add(ip_layer.dst) # dosent add if its already in the set -> set in python makes elements immutable
        
        
        ip_layer = packet[IP]

        if TCP in packet:
            tcp_count += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            udp_count += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            protocol = "UDP"
        else:
            return
        # skip packets that arent tcp or udp -> too much noise to add to the output for now at least

        encrypted = (sport in ENCRYPTED_PORTS or dport in ENCRYPTED_PORTS)
        print(f"[{protocol}] {ip_layer.src}:{sport} → {ip_layer.dst}:{dport} | Encrypted: {'✅' if encrypted else '❌'}") # revised to accept udp




def print_stats():
    runtime = time.time() - start_time
    cap_rate = packet_count / runtime if runtime > 0 else 0
    tcp_pct = (tcp_count / packet_count * 100) if packet_count > 0 else 0
    udp_pct = (udp_count / packet_count * 100) if packet_count > 0 else 0
    print(f"\n{'='*50}")
    print(f"CAPTURE STATISTICS")
    print(f"{'='*50}")
    print(f"Runtime: {runtime:.2f} seconds")
    print(f"Total packets captured: {packet_count}")
    print(f"Packets per second: {cap_rate:.3f}")
    print(f"TCP packets: {tcp_count} ({tcp_pct:.2f}%)")
    print(f"UDP packets: {udp_count} ({udp_pct:.2f}%)")
    print(f"{'='*50}")

print("Packet capturing begin")
try:
    sniff(prn=packet_callback, filter="ip", store=0, count=0)
except KeyboardInterrupt:
    print("\nPacket capturing ended")
print_stats()


