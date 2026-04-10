from scapy.all import rdpcap, TCP
import matplotlib.pyplot as plt

def tcp_flags_graph(pcap_file, label):
    packets = rdpcap(pcap_file)

    syn = ack = fin = rst = 0

    for p in packets:
        if TCP in p:
            flags = p[TCP].flags

            if flags & 0x02:
                syn += 1
            if flags & 0x10:
                ack += 1
            if flags & 0x01:
                fin += 1
            if flags & 0x04:
                rst += 1

    names = ["SYN","ACK","FIN","RST"]
    values = [syn, ack, fin, rst]

    plt.bar(names, values)
    plt.title(f"TCP Flag Distribution ({label})")
    plt.xlabel("TCP Flags")
    plt.ylabel("Count")
    plt.show()


tcp_flags_graph("normal_traffic.pcap", "Normal Traffic")
tcp_flags_graph("medium_traffic.pcap", "Medium Traffic")
tcp_flags_graph("heavy_traffic.pcap", "High Traffic")