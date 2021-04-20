const bit<16> IPV4_ETYPE = 0x0800;
const bit<16> INSTR_PROTO = 0x91;

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            IPV4_ETYPE:     parse_ipv4;
            default:        accept;
        }
    }

    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ethernet.etherType) {
            INSTR_PROTO:     parse_instr;
            default:        accept;
        }
    }

    @name("parse_instr") state parse_instr {
        packet.extract(hdr.instr);
        transition accept;
    }
    
    @name("start") state start {
        transition parse_ethernet;
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.instr);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16);
    }
}
