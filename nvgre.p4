#ifndef P4_PROTOCOL_HEADERS_NVGRE_P4
#define P4_PROTOCOL_HEADERS_NVGRE_P4

/**
 * Network Virtualization using GRE definitions (RFC 7637)
 * 基于 GRE 的网络虚拟化报头，以 VSID 区分虚拟二层网络
 * Wire order: [outer Ethernet][IPv4 or IPv6][NVGRE][inner Ethernet][payload].
 * The inner FCS is omitted. NVGRE carries Ethernet, including non-IP frames.
 * The GRE Key is an identifier, not a cryptographic key.
 */

const bit<8> NVGRE_IP_PROTOCOL = 47;
const bit<16> NVGRE_PROTO_ETHERNET = 0x6558;
const bit<24> NVGRE_VSID_MIN = 0x001000;
const bit<24> NVGRE_VSID_VENDOR = 0xFFFFFF;

/**
 * NVGRE header (8 bytes, GRE base followed by the 32-bit Key)
 * C = 0, K = 1, S = 0 and Version = 0. No checksum or sequence field follows.
 * Protocol Type is always 0x6558. IP payload constants belong to generic GRE.
 * Transmit all reserved bits as zero. On receipt, bit 1 and bits 4-5 must be
 * zero. Bits 6-12 are ignored, following RFC 2784 and RFC 2890.
 * VSIDs 0-0xFFF are reserved. 0xFFFFFF is for vendor NVE-to-NVE communication,
 * rather than a virtual subnet. The sender should verify the peer's vendor.
 * FlowID supplies per-flow entropy and is zero if no FlowID is generated.
 * Transit devices must not modify it. A VSID identifies a network, not a tenant.
 */
header nvgre_t {
    bit<1> c_flag;
    bit<1> reserved0;
    bit<1> k_flag;
    bit<1> s_flag;
    bit<9> reserved1;
    bit<3> version;
    bit<16> protocol;
    bit<24> vsid;
    bit<8> flow_id;
};

/* Inner Ethernet prefix (14 bytes). An endpoint rejects IEEE 802.1Q tags. */
header nvgre_inner_ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> eth_type;
};

struct nvgre_headers_t {
    nvgre_t base;
    nvgre_inner_ethernet_t inner;
};

struct nvgre_metadata_t {
    bit<16> inner_frame_bytes;
    bit<16> payload_bytes;
    bool vendor_specific;
};

/**
 * Bounded endpoint parsing and local delivery example (P4_16, v1model).
 * The cursor points to NVGRE after outer IP validation and protocol 47
 * classification. nvgre_bytes is the validated available IP payload length.
 * IPv4 options and IPv6 extensions precede this cursor. The enclosing pipeline
 * verifies outer lengths and checksums, handles fragmentation and validates
 * the source endpoint. A receiver may discard fragments under RFC 7637.
 *
 * Only NVGRE and the inner Ethernet prefix are extracted. Inner protocol
 * bounds, Ethernet padding and bridge processing belong to the local handler.
 * 0x8100 and 0x88A8 indicate IEEE 802.1Q tags and are rejected by this endpoint.
 * Received reserved bits 6-12, FlowID and the remaining bytes stay unchanged.
 * Reserved low VSIDs are rejected. Vendor communication needs a dedicated
 * configured handler for 0xFFFFFF and does not enter an ordinary subnet.
 *
 * The table delivers the intact tunnel packet to a local bridge or vendor
 * handler. It defaults to drop. FlowID does not select the virtual network.
 * The owner enforces isolation, resolves unknown destinations and determines
 * any broadcast or multicast replication. The enclosing pipeline removes
 * outer headers and prepares egress framing when decapsulating.
 * Emit base, inner Ethernet and the remaining payload in the deparser.
 */
/*
parser nvgre_parser(packet_in pkt, out nvgre_headers_t hdr,
                    out nvgre_metadata_t meta, in bit<16> nvgre_bytes) {
    state start {
        meta.inner_frame_bytes = 0;
        meta.payload_bytes = 0;
        meta.vendor_specific = false;
        verify(nvgre_bytes >= 22, error.HeaderTooShort);
        pkt.extract(hdr.base);
        verify(hdr.base.c_flag == 0 && hdr.base.k_flag == 1
               && hdr.base.s_flag == 0 && hdr.base.version == 0,
               error.NoMatch);
        verify(hdr.base.reserved0 == 0
               && hdr.base.reserved1[8:7] == 0, error.NoMatch);
        verify(hdr.base.protocol == NVGRE_PROTO_ETHERNET, error.NoMatch);
        verify(hdr.base.vsid >= NVGRE_VSID_MIN, error.NoMatch);
        pkt.extract(hdr.inner);
        verify(hdr.inner.eth_type != 0x8100 && hdr.inner.eth_type != 0x88A8,
               error.NoMatch);
        meta.inner_frame_bytes = nvgre_bytes - 8;
        meta.payload_bytes = meta.inner_frame_bytes - 14;
        meta.vendor_specific = hdr.base.vsid == NVGRE_VSID_VENDOR;
        transition accept;
    }
}

control nvgre_control(inout nvgre_headers_t hdr,
                      inout standard_metadata_t standard_metadata) {
    action deliver_nvgre(bit<9> handler_port) {
        standard_metadata.egress_spec = handler_port;
    }

    action drop_nvgre() {
        mark_to_drop(standard_metadata);
    }

    table nvgre_handlers {
        key = {
            hdr.base.vsid: exact;
            hdr.inner.dst_mac: exact;
        }
        actions = {
            deliver_nvgre;
            drop_nvgre;
        }
        default_action = drop_nvgre();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError
            || !hdr.base.isValid() || !hdr.inner.isValid()) {
            mark_to_drop(standard_metadata);
        } else {
            nvgre_handlers.apply();
        }
    }
}
*/

/**
 * NVGRE origination example (v1model).
 * Supply a valid, untagged inner Ethernet frame and its configured VSID.
 * Remove any IEEE 802.1Q tag before calling this example. Frame contents
 * otherwise remain unchanged. Supply per-flow entropy or zero as flow_id.
 * The vendor VSID additionally requires vendor_peer_verified, after the caller
 * has verified the peer and selected the vendor communication handler.
 * The enclosing pipeline adds outer Ethernet and IPv4/IPv6 headers, handles
 * lengths, checksums and underlay MTU, and must not fragment NVGRE packets.
 * Emit base, inner Ethernet and the remaining payload in the deparser.
 */
/*
control nvgre_encapsulation(inout nvgre_headers_t hdr,
                            inout standard_metadata_t standard_metadata,
                            in bit<24> vsid, in bit<8> flow_id,
                            in bool vendor_peer_verified) {
    apply {
        if (!hdr.inner.isValid() || vsid < NVGRE_VSID_MIN
            || (vsid == NVGRE_VSID_VENDOR && !vendor_peer_verified)) {
            mark_to_drop(standard_metadata);
        } else if (hdr.inner.eth_type == 0x8100 || hdr.inner.eth_type == 0x88A8) {
            mark_to_drop(standard_metadata);
        } else {
            hdr.base.setValid();
            hdr.base.c_flag = 0;
            hdr.base.reserved0 = 0;
            hdr.base.k_flag = 1;
            hdr.base.s_flag = 0;
            hdr.base.reserved1 = 0;
            hdr.base.version = 0;
            hdr.base.protocol = NVGRE_PROTO_ETHERNET;
            hdr.base.vsid = vsid;
            hdr.base.flow_id = flow_id;
        }
    }
}
*/

#endif
