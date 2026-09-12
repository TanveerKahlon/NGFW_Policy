/* Longest-prefix-match over IPv4 and IPv6 CIDRs.
 *
 * A binary radix trie: one node per address bit, deepest node carrying a value
 * wins. Chosen over DIR-24-8 because the corpus is tens of thousands of
 * prefixes, not millions — the 32 MB first-level table DIR-24-8 needs would
 * dwarf the data it indexes, and lookup here is still ~32 pointer hops with
 * near-perfect locality at the top of the trie where every lookup begins. */
#ifndef NGFW_LPM_H
#define NGFW_LPM_H

#include <stdint.h>
#include <stddef.h>

#define NGFW_LPM_NO_APP 0xFFFFFFFFU

typedef struct {
    uint32_t app_id;
    uint8_t  tier;
    uint8_t  confidence;
    uint8_t  license_tier;
    uint8_t  prefix_len;      /* specificity: a /24 beats a /8 */
} ngfw_lpm_result_t;

typedef struct ngfw_lpm ngfw_lpm_t;

/* `bits` is 32 for IPv4, 128 for IPv6. */
ngfw_lpm_t *ngfw_lpm_new(uint8_t bits, uint32_t expected_entries);
void        ngfw_lpm_free(ngfw_lpm_t *l);

/* `addr` is network byte order, `bits/8` bytes long. Returns 0 on success. */
int ngfw_lpm_insert(ngfw_lpm_t *l, const uint8_t *addr, uint8_t prefix_len,
                    uint32_t app_id, uint8_t tier, uint8_t confidence,
                    uint8_t license_tier);

/* Returns 1 and fills `out` with the longest matching prefix, 0 on miss. */
int ngfw_lpm_lookup(const ngfw_lpm_t *l, const uint8_t *addr,
                    ngfw_lpm_result_t *out);

size_t ngfw_lpm_node_count(const ngfw_lpm_t *l);

#endif
