#include "ngfw/trie.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LABELS 40
#define EMPTY      0xFFFFFFFFU

typedef struct {
    uint32_t exact_app,  suffix_app;
    uint8_t  exact_tier, suffix_tier;
    uint8_t  exact_conf, suffix_conf;
    uint8_t  exact_lic,  suffix_lic;
} node_t;

/* Edges live in one open-addressed table keyed by (parent, label_hash) rather
 * than a per-node child map. TLD nodes have enormous fan-out and per-node maps
 * would either waste memory or degenerate; one global table keeps probes flat. */
typedef struct {
    uint32_t parent;
    uint32_t child;
    uint64_t hash;
} edge_t;

struct ngfw_trie {
    node_t  *nodes;
    uint32_t node_count, node_cap;
    edge_t  *edges;
    uint32_t edge_mask, edge_used;
};

static uint64_t label_hash(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;          /* FNV-1a, case-folded */
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)(unsigned char)tolower((unsigned char)s[i]);
        h *= 1099511628211ULL;
    }
    return h ? h : 1;                              /* 0 is reserved for "empty" */
}

static uint32_t next_pow2(uint32_t v)
{
    uint32_t p = 16;
    while (p < v) p <<= 1;
    return p;
}

static uint32_t node_new(ngfw_trie_t *t)
{
    if (t->node_count == t->node_cap) {
        uint32_t cap = t->node_cap ? t->node_cap * 2 : 1024;
        node_t *n = realloc(t->nodes, (size_t)cap * sizeof(*n));
        if (!n) return EMPTY;
        t->nodes = n;
        t->node_cap = cap;
    }
    node_t *n = &t->nodes[t->node_count];
    n->exact_app = n->suffix_app = NGFW_TRIE_NO_APP;
    n->exact_tier = n->suffix_tier = 0;
    n->exact_conf = n->suffix_conf = 0;
    n->exact_lic  = n->suffix_lic  = 0;
    return t->node_count++;
}

static int edges_grow(ngfw_trie_t *t);

/* Find the edge slot for (parent,hash). Returns the slot; *found tells whether
 * it is occupied by this key. */
static uint32_t edge_slot(const ngfw_trie_t *t, uint32_t parent, uint64_t hash, int *found)
{
    uint32_t i = (uint32_t)((hash ^ ((uint64_t)parent * 0x9E3779B97F4A7C15ULL)) & t->edge_mask);
    for (;;) {
        const edge_t *e = &t->edges[i];
        if (e->hash == 0) { *found = 0; return i; }
        if (e->hash == hash && e->parent == parent) { *found = 1; return i; }
        i = (i + 1) & t->edge_mask;
    }
}

static uint32_t edge_find(const ngfw_trie_t *t, uint32_t parent, uint64_t hash)
{
    int found;
    uint32_t i = edge_slot(t, parent, hash, &found);
    return found ? t->edges[i].child : EMPTY;
}

static uint32_t edge_insert(ngfw_trie_t *t, uint32_t parent, uint64_t hash, uint32_t child)
{
    if ((t->edge_used + 1) * 10 >= (t->edge_mask + 1) * 7 && edges_grow(t) != 0)
        return EMPTY;
    int found;
    uint32_t i = edge_slot(t, parent, hash, &found);
    if (found) return t->edges[i].child;
    t->edges[i].parent = parent;
    t->edges[i].hash   = hash;
    t->edges[i].child  = child;
    t->edge_used++;
    return child;
}

static int edges_grow(ngfw_trie_t *t)
{
    uint32_t old_cap = t->edge_mask + 1, new_cap = old_cap * 2;
    edge_t *old = t->edges;
    edge_t *ne = calloc(new_cap, sizeof(*ne));
    if (!ne) return -1;

    t->edges = ne;
    t->edge_mask = new_cap - 1;
    for (uint32_t i = 0; i < old_cap; i++) {
        if (old[i].hash == 0) continue;
        int found;
        uint32_t s = edge_slot(t, old[i].parent, old[i].hash, &found);
        t->edges[s] = old[i];
    }
    free(old);
    return 0;
}

/* Split into labels; `out` receives pointers/lengths in FORWARD order. */
static int split_labels(const char *d, const char **out, size_t *len, int max)
{
    size_t n = strlen(d);
    while (n && d[n - 1] == '.') n--;              /* tolerate a root dot */
    if (!n) return 0;

    int count = 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || d[i] == '.') {
            if (i == start) return -1;             /* empty label: malformed */
            if (count >= max) return -1;
            out[count] = d + start;
            len[count] = i - start;
            count++;
            start = i + 1;
        }
    }
    return count;
}

ngfw_trie_t *ngfw_trie_new(uint32_t expected_entries)
{
    ngfw_trie_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;

    uint32_t cap = next_pow2(expected_entries ? expected_entries * 4 : 1024);
    t->edges = calloc(cap, sizeof(*t->edges));
    if (!t->edges) { free(t); return NULL; }
    t->edge_mask = cap - 1;

    if (node_new(t) == EMPTY) {                    /* node 0 = root */
        free(t->edges); free(t);
        return NULL;
    }
    return t;
}

void ngfw_trie_free(ngfw_trie_t *t)
{
    if (!t) return;
    free(t->nodes);
    free(t->edges);
    free(t);
}

int ngfw_trie_insert(ngfw_trie_t *t, const char *domain, uint32_t app_id,
                     int exact, uint8_t tier, uint8_t confidence,
                     uint8_t license_tier)
{
    const char *lab[MAX_LABELS];
    size_t      len[MAX_LABELS];
    int n = split_labels(domain, lab, len, MAX_LABELS);
    if (n <= 0) return -1;

    uint32_t cur = 0;
    for (int i = n - 1; i >= 0; i--) {             /* TLD inward */
        uint64_t h = label_hash(lab[i], len[i]);
        uint32_t nxt = edge_find(t, cur, h);
        if (nxt == EMPTY) {
            nxt = node_new(t);
            if (nxt == EMPTY) return -1;
            if (edge_insert(t, cur, h, nxt) == EMPTY) return -1;
        }
        cur = nxt;
    }

    node_t *nd = &t->nodes[cur];
    /* Higher confidence wins when two sources claim the same name. */
    if (exact) {
        if (nd->exact_app == NGFW_TRIE_NO_APP || confidence > nd->exact_conf) {
            nd->exact_app = app_id; nd->exact_tier = tier;
            nd->exact_conf = confidence; nd->exact_lic = license_tier;
        }
    } else {
        if (nd->suffix_app == NGFW_TRIE_NO_APP || confidence > nd->suffix_conf) {
            nd->suffix_app = app_id; nd->suffix_tier = tier;
            nd->suffix_conf = confidence; nd->suffix_lic = license_tier;
        }
    }
    return 0;
}

int ngfw_trie_lookup(const ngfw_trie_t *t, const char *domain,
                     ngfw_trie_result_t *out)
{
    const char *lab[MAX_LABELS];
    size_t      len[MAX_LABELS];
    int n = split_labels(domain, lab, len, MAX_LABELS);
    if (n <= 0) return 0;

    uint32_t cur = 0;
    int      best_depth = -1;
    const node_t *best_suffix = NULL;

    for (int i = n - 1; i >= 0; i--) {
        uint64_t h = label_hash(lab[i], len[i]);
        uint32_t nxt = edge_find(t, cur, h);
        if (nxt == EMPTY) break;
        cur = nxt;

        const node_t *nd = &t->nodes[cur];
        int depth = n - i;

        /* Full consumption + an exact rule here is the most specific answer. */
        if (i == 0 && nd->exact_app != NGFW_TRIE_NO_APP) {
            out->app_id = nd->exact_app;
            out->tier = nd->exact_tier;
            out->confidence = nd->exact_conf;
            out->license_tier = nd->exact_lic;
            out->matched_exact = 1;
            out->labels_matched = (uint8_t)depth;
            return 1;
        }
        if (nd->suffix_app != NGFW_TRIE_NO_APP) {
            best_suffix = nd;
            best_depth = depth;
        }
    }

    if (!best_suffix) return 0;
    out->app_id = best_suffix->suffix_app;
    out->tier = best_suffix->suffix_tier;
    out->confidence = best_suffix->suffix_conf;
    out->license_tier = best_suffix->suffix_lic;
    out->matched_exact = 0;
    out->labels_matched = (uint8_t)best_depth;
    return 1;
}

size_t ngfw_trie_node_count(const ngfw_trie_t *t) { return t ? t->node_count : 0; }
