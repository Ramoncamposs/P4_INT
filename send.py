#!/usr/bin/env python3
import argparse
import sys
from time import sleep, monotonic_ns
import struct

from scapy.all import (
    IP, UDP, Ether,
    FieldLenField, IntField, BitField, ShortField,
    IPOption, Packet, PacketListField,
    get_if_hwaddr, get_if_list, sendp
)

IP_OPTION_MRI = 31
MAGIC = b"P4TS"              # cabeçalho identificador do nosso payload
HEADER_FMT = "!4sQI"         # magic(4) + t_send_ns(uint64) + seq(uint32)
HEADER_LEN = struct.calcsize(HEADER_FMT)

class SwitchTrace(Packet):
    name = "switch_t"
    fields_desc = [
        IntField("swid", 0),
        BitField("ingress_tstamp", 0, 48),
        BitField("egress_tstamp", 0, 48),
    ]

class IPOption_MRI(IPOption):
    name = "MRI"
    fields_desc = [
        BitField("copy_flag", 1, 1),
        BitField("optclass", 0, 2),
        BitField("option", IP_OPTION_MRI, 5),
        FieldLenField("length", None, length_of="swtraces",
                      adjust=lambda pkt, l: 2 + 2 + l * (4 + 6 + 6)),
        ShortField("count", 0),
        PacketListField("swtraces", [], SwitchTrace,
                        count_from=lambda pkt: pkt.count),
    ]

def get_if():
    for i in get_if_list():
        if "eth0" in i:
            return i
    print("Cannot find eth0 interface")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", help="destination IP address")
    parser.add_argument("message", help="payload message")
    parser.add_argument("count", type=int, nargs="?", default=10)
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between packets")
    args = parser.parse_args()

    iface = get_if()
    print(f"Sending {args.count} packets on interface {iface} to {args.addr}")

    for seq in range(1, args.count + 1):
        t_send_ns = monotonic_ns()
        header = struct.pack(HEADER_FMT, MAGIC, t_send_ns, seq)
        text = f"Packet #{seq}: {args.message}"
        payload = header + text.encode()

        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
              IP(dst=args.addr, options=IPOption_MRI(count=0, swtraces=[])) / \
              UDP(dport=4321, sport=1234) / payload

        sendp(pkt, iface=iface, verbose=False)
        print(f"Sent Packet #{seq}")
        sleep(max(0.0, args.interval))

if __name__ == "__main__":
    main()

