#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, XByteField, IntField
from scapy.all import bind_layers
import readline

class Instr(Packet):
    name = "Instr"
    fields_desc = [ XByteField("opcode", 0),
                    IntField("rd", 0),
                    IntField("rs1", 0),
                    IntField("rs2", 0)]

bind_layers(IP, Instr, protocol=0x91)

def main():

    iface = 'h1-eth0'

    pkt = Ether(dst='00:04:00:00:03:01', src="00:04:00:00:01:01", type=0x800) / IP(src='10.0.0.1', dst='10.0.0.3', protocol=0x91) / Instr(opcode=0x00, rd=0, rs1=0, rs2=0)
    pkt = pkt/' '
    pkt.show()
    resp = srp1(pkt, iface=iface, timeout=1, verbose=True)
    if resp:
        print "hi"
        print resp
    else:
        print "Didn't receive response"

if __name__ == '__main__':
    main()

---------------------------

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, IP, XByteField, IntField
from scapy.all import bind_layers
import readline

class Instr(Packet):
    name = "Instr"
    fields_desc = [ XByteField("opcode", 0),
                    IntField("rd", 0),
                    IntField("rs1", 0),
                    IntField("rs2", 0)]

bind_layers(IP, Instr, protocol=0x91)

iface = 'h1-eth0'

pkt = Ether(dst='00:04:00:00:03:01', src="00:04:00:00:01:01", type=0x800) / IP(src='10.0.0.1', dst='10.0.0.3', proto=0x91) / Instr(opcode=0x00, rd=0, rs1=0, rs2=0)
pkt = pkt/' '
pkt.show()
srp1(pkt, iface=iface, timeout=1, verbose=True)
   