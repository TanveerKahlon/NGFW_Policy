#include "ngfw/lpm.h"

#include <stdlib.h>
#include <string.h>

#define NIL 0xFFFFFFFFU

typedef struct {
    uint32_t child[2];
    uint32_t app_id;
    uint8_t  tier, confidence, license_tier, prefix_len;
} node_t;

struct ngfw_lpm {
    node_t  *nodes;
    uint32_t count, cap;
    uint8_t  bits;
};

static uint32_t node_new(ngfw_lpm_t *l)
{
    if (l->count == l->cap) {
        uint32_t cap = l->cap ? l->cap * 2 : 4096;
        node_t *n = realloc(l->nodes, (size_t)cap * sizeof(*n));
        if (!n) return NIL;
        l->nodes = n;
        l->cap = cap;
    }
    node_t *n = &l->nodes[l->count];
    n->child[0] = n->child[1] = NIL;
    n->app_id = NGFW_LPM_NO_APP;
    n->tier = n->confidence = n->license_tier = n->prefix_len = 0;
    return l->count++;
}

static int bit_at(const uint8_t *addr, uint8_t i)
{
    return (addr[i >> 3] >> (7 - (i & 7))) & 1;
}

ngfw_lpm_t *ngfw_lpm_new(uint8_t bits, uint32_t expected_entries)
{
    if (bits != 32 && bits != 128) return NULL;

    ngfw_lpm_t *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->bits = bits;

    /* Most prefixes share a long head with a sibling, so nodes-per-prefix is
     * far below `bits` in practice; this is a starting point, not a bound. */
    l->cap = expected_entries ? expected_entries * 4 : 4096;
    l->nodes = malloc((size_t)l->cap * sizeof(*l->nodes));
    if (!l->nodes) { free(l); return NULL; }

    if (node_new(l) == NIL) { free(l->nodes); free(l); return NULL; }
    return l;
}

void ngfw_lpm_free(ngfw_lpm_t *l)
{
    if (!l) return;
    free(l->nodes);
    free(l);
}

int ngfw_lpm_insert(ngfw_lpm_t *l, const uint8_t *addr, uint8_t prefix_len,
                    uint32_t app_id, uint8_t tier, uint8_t confidence,
                    uint8_t license_tier)
{
    if (!l || prefix_len > l->bits) return -1;

    uint32_t cur = 0;
    for (uint8_t i = 0; i < prefix_len; i++) {
        int b = bit_at(addr, i);
        uint32_t nxt = l->nodes[cur].child[b];
        if (nxt == NIL) {
            nxt = node_new(l);
            if (nxt == NIL) return -1;
            l->nodes[cur].child[b] = nxt;   /* after realloc: index, not pointer */
        }
        cur = nxt;
    }

    node_t *n = &l->nodes[cur];
    /* Two sources may claim the same prefix; keep the more confident one. */
    if (n->app_id == NGFW_LPM_NO_APP || confidence > n->confidence) {
        n->app_id = app_id;
        n->tier = tier;
        n->confidence = confidence;
        n->license_tier = license_tier;
        n->prefix_len = prefix_len;
    }
    return 0;
}

int ngfw_lpm_lookup(const ngfw_lpm_t *l, const uint8_t *addr,
                    ngfw_lpm_result_t *out)
{
    if (!l) return 0;

    uint32_t cur = 0;
    const node_t *best = NULL;

    if (l->nodes[0].app_id != NGFW_LPM_NO_APP) best = &l->nodes[0];  /* ::/0 */

    for (uint8_t i = 0; i < l->bits; i++) {
        uint32_t nxt = l->nodes[cur].child[bit_at(addr, i)];
        if (nxt == NIL) break;
        cur = nxt;
        if (l->nodes[cur].app_id != NGFW_LPM_NO_APP) best = &l->nodes[cur];
    }

    if (!best) return 0;
    out->app_id = best->app_id;
    out->tier = best->tier;
    out->confidence = best->confidence;
    out->license_tier = best->license_tier;
    out->prefix_len = best->prefix_len;
    return 1;
}

size_t ngfw_lpm_node_count(const ngfw_lpm_t *l) { return l ? l->count : 0; }
