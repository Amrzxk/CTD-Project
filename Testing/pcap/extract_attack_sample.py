"""
Extract a CONTIGUOUS block of packets from the attack window of the CIC-IDS PCAPNG.

Instead of sampling from scattered offsets, we grab one large contiguous 
block from deep in the file where attacks are happening.

Wednesday CIC-IDS 2017 attacks start ~20 min in (Slowloris), with 
DoS Hulk being the most volumetric at ~35 min in.

We skip to ~2M packets in (mid-file, attack territory) and grab 
10,000 contiguous packets. This gives NFStream enough per-flow packets
to compute meaningful features.
"""

import os
import sys

INPUT  = r"F:\GradProject\Testing\pcap\Wednesday-workingHours.8FLhsdtM.pcap.part"
OUTPUT = r"F:\GradProject\Testing\pcap\test_attack_sample.pcap"

SKIP_PACKETS = 2_000_000   # Skip into attack territory
GRAB_PACKETS = 10_000      # Grab 10k contiguous packets


def main():
    from scapy.utils import PcapNgReader
    import dpkt

    file_size = os.path.getsize(INPUT)
    print(f"Input: {INPUT} ({file_size / (1024**3):.2f} GB)")
    print(f"Strategy: skip {SKIP_PACKETS:,} packets, grab {GRAB_PACKETS:,} contiguous packets")
    print()

    print(f"Skipping to packet {SKIP_PACKETS:,}...", flush=True)
    reader = PcapNgReader(INPUT)
    
    packets = []
    count = 0
    
    for pkt in reader:
        count += 1
        if count % 200000 == 0:
            print(f"  Skipped {count:,}/{SKIP_PACKETS:,}...", flush=True)
        
        if count <= SKIP_PACKETS:
            continue
        
        packets.append(bytes(pkt))
        
        if len(packets) >= GRAB_PACKETS:
            break
    
    reader.close()
    
    if not packets:
        print("ERROR: No packets collected!")
        sys.exit(1)
    
    print(f"\nCollected {len(packets):,} contiguous packets from offset {SKIP_PACKETS:,}")
    
    # Write as standard PCAP
    print(f"Writing to {OUTPUT}...", flush=True)
    with open(OUTPUT, 'wb') as f:
        writer = dpkt.pcap.Writer(f)
        for raw in packets:
            writer.writepkt(raw)
    
    output_size = os.path.getsize(OUTPUT)
    print(f"Done! Output: {output_size / (1024**2):.1f} MB, {len(packets):,} packets")


if __name__ == "__main__":
    main()
