#include "ngfw/decode.h"

#include <string.h>

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_IPV6  0x86DD
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_QINQ  0x88A8

#define DLT_NULL        0
#define DLT_EN10MB      1
#define DLT_RAW         101
#define DLT_LINUX_SLL   113

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static int decode_l4(const uint8_t *p, uint32_t len, ngfw_packet_t *out)
{
    if (out->l4proto == NGFW_L4_TCP) {
        if (len < 20) return -1;
        out->src_port = rd16(p);
        out->dst_port = rd16(p + 2);
        uint32_t hlen = (uint32_t)((p[12] >> 4) * 4);
        if (hlen < 20 || hlen > len) return -1;
        out->payload = p + hlen;
        out->payload_len = len - hlen;
        return 0;
    }
    if (out->l4proto == NGFW_L4_UDP) {
        if (len < 8) return -1;
        out->src_port = rd16(p);
        out->dst_port = rd16(p + 2);
        out->payload = p + 8;
        out->payload_len = len - 8;
        return 0;
    }
    out->payload = NULL;
    out->payload_len = 0;
    return 0;
}

static int decode_ip(const uint8_t *p, uint32_t len, ngfw_packet_t *out)
{
    if (len < 1) return -1;
    uint8_t ver = p[0] >> 4;

    if (ver == 4) {
        if (len < 20) return -1;
        uint32_t ihl = (uint32_t)((p[0] & 0x0F) * 4);
        if (ihl < 20 || ihl > len) return -1;

        out->ip_version = 4;
        out->l4proto = p[9];
        memcpy(out->src_ip, p + 12, 4);
        memcpy(out->dst_ip, p + 16, 4);

        /* Only the first fragment carries an L4 header worth reading. */
        uint16_t frag = rd16(p + 6);
        if ((frag & 0x1FFF) != 0) { out->payload = NULL; out->payload_len = 0; return 0; }

        return decode_l4(p + ihl, len - ihl, out);
    }

    if (ver == 6) {
        if (len < 40) return -1;
        out->ip_version = 6;
        memcpy(out->src_ip, p + 8, 16);
        memcpy(out->dst_ip, p + 24, 16);

        uint8_t  nh  = p[6];
        uint32_t off = 40;
        /* Walk the common extension headers to reach the transport header. */
        for (int i = 0; i < 8; i++) {
            if (nh == 0 || nh == 43 || nh == 60) {          /* hop-by-hop, routing, dest */
                if (off + 8 > len) return -1;
                uint32_t elen = (uint32_t)((p[off + 1] + 1) * 8);
                nh = p[off];
                off += elen;
                if (off > len) return -1;
            } else if (nh == 44) {                          /* fragment */
                if (off + 8 > len) return -1;
                nh = p[off];
                off += 8;
            } else {
                break;
            }
        }
        out->l4proto = nh;
        if (off > len) return -1;
        return decode_l4(p + off, len - off, out);
    }
    return -1;
}

int ngfw_decode(const uint8_t *pkt, uint32_t caplen, uint32_t linktype,
                ngfw_packet_t *out)
{
    memset(out, 0, sizeof(*out));

    switch (linktype) {
    case DLT_EN10MB: {
        if (caplen < 14) return -1;
        uint16_t et = rd16(pkt + 12);
        uint32_t off = 14;
        /* Peel up to two VLAN tags (QinQ). */
        for (int i = 0; i < 2 && (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ); i++) {
            if (caplen < off + 4) return -1;
            et = rd16(pkt + off + 2);
            off += 4;
        }
        if (et != ETHERTYPE_IP && et != ETHERTYPE_IPV6) return -1;
        return decode_ip(pkt + off, caplen - off, out);
    }
    case DLT_RAW:
        return decode_ip(pkt, caplen, out);
    case DLT_NULL:
        if (caplen < 4) return -1;
        return decode_ip(pkt + 4, caplen - 4, out);
    case DLT_LINUX_SLL:
        if (caplen < 16) return -1;
        return decode_ip(pkt + 16, caplen - 16, out);
    default:
        return -1;
    }
}
