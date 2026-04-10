from scapy.all import rdpcap, TCP
import matplotlib.pyplot as plt

def packet_size_graph(pcap_file, label):
    packets = rdpcap(pcap_file)

    sizes = []

    for p in packets:
        if TCP in p:
            sizes.append(len(p))

    plt.hist(sizes)
    plt.title(f"TCP Packet Size Distribution ({label})")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Number of Packets")
    plt.show()


packet_size_graph("normal_traffic.pcapng", "Normal Traffic")
packet_size_graph("medium_traffic.pcapng", "Medium Traffic")
packet_size_graph("heavy_traffic.pcapng", "High Traffic")