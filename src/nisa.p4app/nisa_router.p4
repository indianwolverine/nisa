#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

const bit<8> INSTR_RTS = 0x00;
const bit<8> INSTR_RTS_IFQ = 0x01;

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    @name("_drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name("send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("_drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name("set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.ingress_metadata.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    @name("set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    @name("instr_rts") action instr_rts() {
        // Return to Sender
        bit<48> tmp;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    @name("instr_rts_ifq") action instr_rts_ifq() {
        // If queue is longer than X, return to sender with rd = queue length
        bit<32> queue_len = (bit<32>) standard_metadata.enq_qdepth;
        if (queue_len > hdr.instr.rs1) {
            hdr.instr.rd = queue_len;
            instr_rts();
        }
    }

    @name("ipv4_lpm") table ipv4_lpm {
        actions = {
            _drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }

    @name("forward") table forward {
        actions = {
            set_dmac;
            _drop;
            NoAction;
        }
        key = {
            meta.ingress_metadata.nhop_ipv4: exact;
        }
        size = 512;
        default_action = NoAction();
    }

    @name("exec_instr") table exec_instr {
        key = {
            hdr.instr.opcode : exact;
        }
        actions = {
            _drop;
            instr_rts;
            instr_rts_ifq;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            INSTR_RTS : instr_rts();
            INSTR_RTS_IFQ : instr_rts_ifq();
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          forward.apply();
        }
        if (hdr.instr.isValid()) {
          exec_instr.apply();
        } 
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
