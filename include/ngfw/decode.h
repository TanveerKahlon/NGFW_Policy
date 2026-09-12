/* Link/network/transport decode, and TLS ClientHello SNI extraction. */
#ifndef NGFW_DECODE_H
#define NGFW_DECODE_H

#include <stdint.h>
#include <stddef.h>

enum { NGFW_L4_OTHER = 0, NGFW_L4_TCP = 6, NGFW_L4_UDP = 17 };

typedef struct {
    uint8_t  ip_version;          /* 4, 6, or 0 if undecoded */
    uint8_t  l4proto;
    uint8_t  src_ip[16], dst_ip[16];
    uint16_t src_port, dst_port;
    const uint8_t *payload;       /* L4 payload, may be NULL */
    uint32_t payload_len;
} ngfw_packet_t;

/* Decode from the Ethernet header. Returns 0 on success, -1 if the packet is
 * truncated or not a protocol we handle. */
int ngfw_decode(const uint8_t *pkt, uint32_t caplen, uint32_t linktype,
                ngfw_packet_t *out);

/* Extract the SNI hostname from a TLS ClientHello. `buf` is the start of the
 * TCP payload. Returns 1 and fills `sni` (NUL-terminated) on success. */
int ngfw_tls_sni(const uint8_t *buf, uint32_t len, char *sni, size_t sni_cap);

/* QUIC long-header Initial packets also carry a ClientHello, but reaching it
 * needs header protection removal and AEAD decryption of the CRYPTO frame.
 * Deliberately deferred; declared so the call site exists. */
int ngfw_quic_sni(const uint8_t *buf, uint32_t len, char *sni, size_t sni_cap);

#endif
