import matplotlib.pyplot as plt
from scapy.all import rdpcap

def get_cumulative_data(pcap_file):
    packets = rdpcap(pcap_file)
    start_time = packets[0].time
    times = []
    cumulative_bytes = []
    total_bytes = 0
    
    for pkt in packets:
        if pkt.haslayer('TCP'):
            total_bytes += len(pkt)
            times.append(float(pkt.time - start_time))
            cumulative_bytes.append(total_bytes / 1024) # Convert to KB
            
    return times, cumulative_bytes

# Process your files
files = {
    "Normal": "normal_traffic.pcapng",
    "Medium": "medium_traffic.pcapng",
    "Heavy": "heavy_traffic.pcapng"
}

plt.figure(figsize=(10, 6))

for label, path in files.items():
    try:
        x, y = get_cumulative_data(path)
        plt.plot(x, y, label=f"{label} Traffic")
    except Exception as e:
        print(f"Could not process {label}: {e}")

plt.title("Comparative Cumulative TCP Throughput", fontsize=14)
plt.xlabel("Time (seconds)", fontsize=12)
plt.ylabel("Cumulative Data Transferred (KB)", fontsize=12)
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)
plt.show()