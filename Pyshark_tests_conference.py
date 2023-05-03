import pyshark
import csv
import numpy as np
from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
import ipaddress

# The path to the .pcap file
packet_path = r"<file_path>Packet_capture_FULL.pcap"

# Get hold of the information received after parsing the .pcap file with the FileCapture function
capture = pyshark.FileCapture(packet_path)

with open("output_results_tor_conference_version.csv", "w", newline="") as csvfile:
    # Create the CSV writer instance which will assist us with the insertion of the data into the CSV file
    writer = csv.writer(csvfile)

    # Write the Column Titles
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "packet length", "protocol"])

    # Iterate over the packets to get the needed information
    for packet in capture:
        timestamp = packet.sniff_timestamp
        src_ip = packet.ip.src if "IP" in packet else "10.0.0.0"
        dst_ip = packet.ip.dst if "IP" in packet else ""
        length = packet.length
        protocol = packet.highest_layer

        # Write the data to the CSV file
        writer.writerow([timestamp, src_ip, dst_ip, length, protocol])





