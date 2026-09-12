/* 4-byte payload-prefix matcher with wildcard masks.
 *
 * Patterns are bucketed by mask: there are at most 16 distinct masks over four
 * bytes, so a lookup is a handful of hash probes rather than a scan over every
 * pattern. Exact (fully specified) patterns dominate and resolve in one probe. */
#ifndef NGFW_PAYLOAD_H
#define NGFW_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t app_id;
    uint8_t  tier;
    uint8_t  confidence;
    uint8_t  license_tier;
    uint8_t  wildcards;     /* specificity: fewer wildcards is a tighter match */
} ngfw_payload_result_t;

typedef struct ngfw_payload_set ngfw_payload_set_t;

ngfw_payload_set_t *ngfw_payload_new(uint32_t expected);
void                ngfw_payload_free(ngfw_payload_set_t *p);

int ngfw_payload_insert(ngfw_payload_set_t *p, const uint8_t value[4],
                        const uint8_t mask[4], uint32_t app_id, uint8_t tier,
                        uint8_t confidence, uint8_t license_tier);

/* `buf` must hold at least 4 bytes. Returns 1 on the tightest match found. */
int ngfw_payload_lookup(const ngfw_payload_set_t *p, const uint8_t *buf,
                        uint32_t len, ngfw_payload_result_t *out);

size_t ngfw_payload_count(const ngfw_payload_set_t *p);

#endif
