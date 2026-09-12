#include "ngfw/payload.h"

#include <stdlib.h>
#include <string.h>

#define NBUCKETS 16          /* one per combination of wildcarded bytes */
#define EMPTY    0xFFFFFFFFU

typedef struct {
    uint32_t key;            /* value & mask, as a big-endian u32 */
    uint32_t app_id;
    uint8_t  tier, confidence, license_tier, used;
} entry_t;

typedef struct {
    entry_t *slots;
    uint32_t mask_bits;      /* table size - 1 */
    uint32_t count;
    uint32_t bytemask;       /* the 4-byte mask this bucket holds */
    uint8_t  wildcards;
    uint8_t  active;
} bucket_t;

struct ngfw_payload_set {
    bucket_t buckets[NBUCKETS];
    uint32_t total;
};

static uint32_t be32(const uint8_t b[4])
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
}

/* Index a mask by which of its four bytes are wildcards. */
static int mask_index(const uint8_t mask[4])
{
    int idx = 0;
    for (int i = 0; i < 4; i++)
        if (mask[i] == 0) idx |= (1 << i);
    return idx;
}

static uint32_t mix(uint32_t x)
{
    x ^= x >> 16; x *= 0x7feb352dU;
    x ^= x >> 15; x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static int bucket_init(bucket_t *b, uint32_t expected)
{
    uint32_t cap = 64;
    while (cap < expected * 2) cap <<= 1;
    b->slots = calloc(cap, sizeof(*b->slots));
    if (!b->slots) return -1;
    b->mask_bits = cap - 1;
    b->active = 1;
    return 0;
}

ngfw_payload_set_t *ngfw_payload_new(uint32_t expected)
{
    ngfw_payload_set_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    (void)expected;
    return p;
}

void ngfw_payload_free(ngfw_payload_set_t *p)
{
    if (!p) return;
    for (int i = 0; i < NBUCKETS; i++) free(p->buckets[i].slots);
    free(p);
}

int ngfw_payload_insert(ngfw_payload_set_t *p, const uint8_t value[4],
                        const uint8_t mask[4], uint32_t app_id, uint8_t tier,
                        uint8_t confidence, uint8_t license_tier)
{
    /* An all-wildcard pattern matches every flow. The compiler already refuses
     * to emit one, but the database is untrusted input at load time, so refuse
     * it here too rather than trusting the producer. */
    if ((mask[0] | mask[1] | mask[2] | mask[3]) == 0) return -1;

    int bi = mask_index(mask);
    bucket_t *b = &p->buckets[bi];

    if (!b->active) {
        if (bucket_init(b, 256) != 0) return -1;
        b->bytemask = be32(mask);
        b->wildcards = 0;
        for (int i = 0; i < 4; i++) if (mask[i] == 0) b->wildcards++;
    }

    /* Grow before the table gets dense enough to lengthen probe chains. */
    if ((b->count + 1) * 10 >= (b->mask_bits + 1) * 7) {
        uint32_t old_cap = b->mask_bits + 1, cap = old_cap * 2;
        entry_t *old = b->slots, *ns = calloc(cap, sizeof(*ns));
        if (!ns) return -1;
        b->slots = ns;
        b->mask_bits = cap - 1;
        for (uint32_t i = 0; i < old_cap; i++) {
            if (!old[i].used) continue;
            uint32_t j = mix(old[i].key) & b->mask_bits;
            while (b->slots[j].used) j = (j + 1) & b->mask_bits;
            b->slots[j] = old[i];
        }
        free(old);
    }

    uint32_t key = be32(value) & b->bytemask;
    uint32_t i = mix(key) & b->mask_bits;
    while (b->slots[i].used) {
        if (b->slots[i].key == key) {
            /* Same pattern claimed twice: keep the more confident source. */
            if (confidence > b->slots[i].confidence) {
                b->slots[i].app_id = app_id;
                b->slots[i].tier = tier;
                b->slots[i].confidence = confidence;
                b->slots[i].license_tier = license_tier;
            }
            return 0;
        }
        i = (i + 1) & b->mask_bits;
    }

    b->slots[i] = (entry_t){ key, app_id, tier, confidence, license_tier, 1 };
    b->count++;
    p->total++;
    return 0;
}

int ngfw_payload_lookup(const ngfw_payload_set_t *p, const uint8_t *buf,
                        uint32_t len, ngfw_payload_result_t *out)
{
    if (!p || len < 4) return 0;

    uint32_t word = be32(buf);
    int found = 0;
    uint8_t best_wildcards = 5;

    for (int bi = 0; bi < NBUCKETS; bi++) {
        const bucket_t *b = &p->buckets[bi];
        if (!b->active || b->count == 0) continue;
        /* A looser pattern cannot beat a tighter one already found. */
        if (found && b->wildcards >= best_wildcards) continue;

        uint32_t key = word & b->bytemask;
        uint32_t i = mix(key) & b->mask_bits;
        for (uint32_t probe = 0; probe <= b->mask_bits; probe++) {
            const entry_t *e = &b->slots[i];
            if (!e->used) break;
            if (e->key == key) {
                out->app_id = e->app_id;
                out->tier = e->tier;
                out->confidence = e->confidence;
                out->license_tier = e->license_tier;
                out->wildcards = b->wildcards;
                best_wildcards = b->wildcards;
                found = 1;
                break;
            }
            i = (i + 1) & b->mask_bits;
        }
    }
    return found;
}

size_t ngfw_payload_count(const ngfw_payload_set_t *p) { return p ? p->total : 0; }
