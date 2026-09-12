/* Flow table with a revisable verdict.
 *
 * The verdict callback fires more than once per flow: a provisional answer as
 * early as packet 1, then a correction when better evidence arrives (the SNI is
 * typically in packet 3 of a TCP flow). A policy engine needs the fast answer to
 * decide whether to forward at all, and the accurate one to log and enforce.
 * Retrofitting revision later means touching every consumer, so it is in from
 * the start. */
#ifndef NGFW_FLOW_H
#define NGFW_FLOW_H

#include <stdint.h>
#include "ngfw/decode.h"

#define NGFW_APP_UNKNOWN 0xFFFFFFFFU

typedef struct {
    /* Two identities, as nDPI models it.
     *
     * `master_app_id` is the PROTOCOL on the wire (tls, bittorrent, ssh) and
     * comes from byte-pattern evidence. `app_id` is the APPLICATION (netflix,
     * dropbox) and comes from names and addresses.
     *
     * Keeping them apart matters: a payload signature for TLS is stronger
     * evidence than an SNI in the durability sense, but answering "tls" when
     * the flow is Netflix is useless to a policy engine. Protocol evidence
     * fills the app slot only when nothing more specific is known. */
    uint32_t master_app_id;
    uint32_t app_id;
    uint8_t  master_confidence;
    uint8_t  master_tier;
    uint8_t  confidence;
    uint8_t  tier;
    uint8_t  license_tier;
    uint8_t  is_final;
    uint32_t evidence_mask;      /* which matchers contributed */
} ngfw_verdict_t;

enum {
    NGFW_EV_SNI  = 1u << 0,
    NGFW_EV_PAYLOAD = 1u << 4,
    NGFW_EV_PORT = 1u << 1,
    NGFW_EV_IP   = 1u << 2,
    NGFW_EV_JA4  = 1u << 3
};

typedef struct {
    uint8_t  src_ip[16], dst_ip[16];
    uint16_t src_port, dst_port;
    uint8_t  l4proto, ip_version;
    uint8_t  in_use;
    uint16_t packets;
    ngfw_verdict_t verdict;
} ngfw_flow_t;

typedef struct ngfw_flow_table ngfw_flow_table_t;

ngfw_flow_table_t *ngfw_flow_table_new(uint32_t capacity);
void               ngfw_flow_table_free(ngfw_flow_table_t *ft);

/* Returns the flow for this packet, creating it if new. `is_new` is optional.
 * Direction-agnostic: A->B and B->A map to the same flow. */
ngfw_flow_t *ngfw_flow_lookup(ngfw_flow_table_t *ft, const ngfw_packet_t *pkt,
                              int *is_new);

uint32_t ngfw_flow_count(const ngfw_flow_table_t *ft);
uint32_t ngfw_flow_evictions(const ngfw_flow_table_t *ft);

#endif
