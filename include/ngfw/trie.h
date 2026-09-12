/* Reversed-label domain trie.
 *
 * Domains are hierarchical label sequences, not substrings, so this walks
 * labels from the TLD inward rather than running an Aho-Corasick automaton over
 * bytes. That gives label-boundary correctness for free: "notnetflix.com" can
 * never match a "netflix.com" suffix rule, which is the classic false-positive
 * bug in substring-based matchers.
 *
 * Each node carries both an exact and a suffix verdict, so one walk resolves
 * both match kinds. Exact wins over suffix; the deepest suffix wins over
 * shallower ones. */
#ifndef NGFW_TRIE_H
#define NGFW_TRIE_H

#include <stdint.h>
#include <stddef.h>

#define NGFW_TRIE_NO_APP 0xFFFFFFFFU

typedef struct {
    uint32_t app_id;
    uint8_t  tier;
    uint8_t  confidence;
    uint8_t  license_tier;
    uint8_t  matched_exact;
    uint8_t  labels_matched;   /* specificity: deeper match wins ties */
} ngfw_trie_result_t;

typedef struct ngfw_trie ngfw_trie_t;

ngfw_trie_t *ngfw_trie_new(uint32_t expected_entries);
void         ngfw_trie_free(ngfw_trie_t *t);

/* `domain` is forward-ordered ("www.netflix.com"); the trie reverses internally.
 * Returns 0 on success. */
int ngfw_trie_insert(ngfw_trie_t *t, const char *domain, uint32_t app_id,
                     int exact, uint8_t tier, uint8_t confidence,
                     uint8_t license_tier);

/* Returns 1 and fills `out` on a hit, 0 on miss. Case-insensitive; a single
 * trailing dot is tolerated. */
int ngfw_trie_lookup(const ngfw_trie_t *t, const char *domain,
                     ngfw_trie_result_t *out);

size_t ngfw_trie_node_count(const ngfw_trie_t *t);

#endif
