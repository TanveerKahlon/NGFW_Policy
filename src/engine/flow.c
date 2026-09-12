#include "ngfw/flow.h"

#include <stdlib.h>
#include <string.h>

struct ngfw_flow_table {
    ngfw_flow_t *slots;
    uint32_t     mask;
    uint32_t     count;
    uint32_t     evictions;
};

static uint32_t next_pow2(uint32_t v)
{
    uint32_t p = 1024;
    while (p < v) p <<= 1;
    return p;
}

/* splitmix64 finalizer: full avalanche, so every input bit affects every output
 * bit. Without it the low bits — which is all the bucket mask uses — stay
 * correlated with the ephemeral port, and sequential ports from one host pile
 * into a handful of probe chains. That showed up as mass eviction at 3% load. */
static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

/* Hash the 5-tuple such that both directions land on the same bucket. */
static uint64_t flow_hash(const ngfw_packet_t *p)
{
    int alen = (p->ip_version == 6) ? 16 : 4;

    uint64_t a = 0xcbf29ce484222325ULL, b = 0xcbf29ce484222325ULL;
    for (int i = 0; i < alen; i++) {
        a = (a ^ p->src_ip[i]) * 1099511628211ULL;
        b = (b ^ p->dst_ip[i]) * 1099511628211ULL;
    }
    a = mix64(a ^ p->src_port);
    b = mix64(b ^ p->dst_port);

    /* Symmetric in (a,b) so A->B and B->A hash alike, then avalanche again. */
    return mix64((a ^ b) + (a & b) + p->l4proto);
}

static int same_flow(const ngfw_flow_t *f, const ngfw_packet_t *p)
{
    if (f->l4proto != p->l4proto || f->ip_version != p->ip_version) return 0;
    int alen = (p->ip_version == 6) ? 16 : 4;

    int fwd = f->src_port == p->src_port && f->dst_port == p->dst_port &&
              memcmp(f->src_ip, p->src_ip, alen) == 0 &&
              memcmp(f->dst_ip, p->dst_ip, alen) == 0;
    int rev = f->src_port == p->dst_port && f->dst_port == p->src_port &&
              memcmp(f->src_ip, p->dst_ip, alen) == 0 &&
              memcmp(f->dst_ip, p->src_ip, alen) == 0;
    return fwd || rev;
}

ngfw_flow_table_t *ngfw_flow_table_new(uint32_t capacity)
{
    ngfw_flow_table_t *ft = calloc(1, sizeof(*ft));
    if (!ft) return NULL;

    uint32_t cap = next_pow2(capacity ? capacity * 2 : 65536);
    ft->slots = calloc(cap, sizeof(*ft->slots));
    if (!ft->slots) { free(ft); return NULL; }
    ft->mask = cap - 1;
    return ft;
}

void ngfw_flow_table_free(ngfw_flow_table_t *ft)
{
    if (!ft) return;
    free(ft->slots);
    free(ft);
}

ngfw_flow_t *ngfw_flow_lookup(ngfw_flow_table_t *ft, const ngfw_packet_t *pkt,
                              int *is_new)
{
    if (is_new) *is_new = 0;

    uint32_t i = (uint32_t)(flow_hash(pkt) & ft->mask);
    /* Bounded linear probe; beyond this we evict rather than scan the table. */
    for (int probe = 0; probe < 16; probe++) {
        ngfw_flow_t *f = &ft->slots[(i + probe) & ft->mask];
        if (!f->in_use) {
            memset(f, 0, sizeof(*f));
            f->in_use = 1;
            f->ip_version = pkt->ip_version;
            f->l4proto = pkt->l4proto;
            memcpy(f->src_ip, pkt->src_ip, 16);
            memcpy(f->dst_ip, pkt->dst_ip, 16);
            f->src_port = pkt->src_port;
            f->dst_port = pkt->dst_port;
            f->verdict.app_id = NGFW_APP_UNKNOWN;
            f->verdict.master_app_id = NGFW_APP_UNKNOWN;
            ft->count++;
            if (is_new) *is_new = 1;
            return f;
        }
        if (same_flow(f, pkt)) return f;
    }

    /* Table pressure: reuse the home slot. Offline analysis only — a live
     * datapath needs proper timeout-based eviction. */
    ngfw_flow_t *f = &ft->slots[i];
    memset(f, 0, sizeof(*f));
    f->in_use = 1;
    f->ip_version = pkt->ip_version;
    f->l4proto = pkt->l4proto;
    memcpy(f->src_ip, pkt->src_ip, 16);
    memcpy(f->dst_ip, pkt->dst_ip, 16);
    f->src_port = pkt->src_port;
    f->dst_port = pkt->dst_port;
    f->verdict.app_id = NGFW_APP_UNKNOWN;
    f->verdict.master_app_id = NGFW_APP_UNKNOWN;
    ft->evictions++;
    if (is_new) *is_new = 1;
    return f;
}

uint32_t ngfw_flow_count(const ngfw_flow_table_t *ft) { return ft ? ft->count : 0; }
uint32_t ngfw_flow_evictions(const ngfw_flow_table_t *ft) { return ft ? ft->evictions : 0; }
