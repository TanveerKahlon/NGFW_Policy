/* Unit tests for the reversed-label domain trie.
 *
 * The label-boundary cases are the point: substring matchers get these wrong,
 * and getting them wrong means confidently misattributing traffic. */
#include "ngfw/trie.h"

#include <stdio.h>
#include <string.h>

static int failures = 0, checks = 0;

#define CHECK(cond, ...) do {                                  \
    checks++;                                                  \
    if (!(cond)) {                                             \
        failures++;                                            \
        printf("  FAIL %s:%d  ", __FILE__, __LINE__);          \
        printf(__VA_ARGS__);                                   \
        printf("\n");                                          \
    }                                                          \
} while (0)

#define APP_NETFLIX 100
#define APP_GOOGLE  200
#define APP_DRIVE   201
#define APP_EVIL    300

static int lookup_app(const ngfw_trie_t *t, const char *host)
{
    ngfw_trie_result_t r;
    return ngfw_trie_lookup(t, host, &r) ? (int)r.app_id : -1;
}

int main(void)
{
    printf("domain trie\n");

    ngfw_trie_t *t = ngfw_trie_new(64);
    if (!t) { printf("  FAIL: allocation\n"); return 1; }

    ngfw_trie_insert(t, "netflix.com",     APP_NETFLIX, 0, 1, 85, 0);
    ngfw_trie_insert(t, "google.com",      APP_GOOGLE,  0, 1, 80, 0);
    ngfw_trie_insert(t, "drive.google.com", APP_DRIVE,  1, 1, 95, 0);

    /* --- basic suffix behaviour --- */
    CHECK(lookup_app(t, "netflix.com") == APP_NETFLIX, "apex should match suffix rule");
    CHECK(lookup_app(t, "www.netflix.com") == APP_NETFLIX, "subdomain should match");
    CHECK(lookup_app(t, "a.b.c.netflix.com") == APP_NETFLIX, "deep subdomain should match");

    /* --- label-boundary correctness: the whole reason for a label trie --- */
    CHECK(lookup_app(t, "notnetflix.com") == -1,
          "notnetflix.com must NOT match netflix.com");
    CHECK(lookup_app(t, "netflix.com.evil.tld") == -1,
          "netflix.com.evil.tld must NOT match (suffix is evil.tld)");
    CHECK(lookup_app(t, "xnetflix.com") == -1, "xnetflix.com must NOT match");
    CHECK(lookup_app(t, "netflix.company.com") == -1,
          "netflix.company.com must NOT match");

    /* --- specificity: deepest/exact wins --- */
    CHECK(lookup_app(t, "drive.google.com") == APP_DRIVE,
          "exact rule must beat the shallower suffix rule");
    CHECK(lookup_app(t, "mail.google.com") == APP_GOOGLE,
          "unlisted subdomain falls back to the suffix rule");
    CHECK(lookup_app(t, "x.drive.google.com") == APP_GOOGLE,
          "exact rule must NOT match deeper names");

    /* --- case and trailing dot --- */
    CHECK(lookup_app(t, "WWW.NetFlix.COM") == APP_NETFLIX, "matching is case-insensitive");
    CHECK(lookup_app(t, "www.netflix.com.") == APP_NETFLIX, "a root dot is tolerated");

    /* --- misses and malformed input must not crash or match --- */
    CHECK(lookup_app(t, "example.com") == -1, "unrelated domain misses");
    CHECK(lookup_app(t, "com") == -1, "bare TLD misses");
    CHECK(lookup_app(t, "") == -1, "empty string misses");
    CHECK(lookup_app(t, ".") == -1, "lone dot misses");
    CHECK(lookup_app(t, "..") == -1, "double dot misses");
    CHECK(lookup_app(t, "a..b") == -1, "empty label is malformed");

    /* --- metadata survives the round trip --- */
    ngfw_trie_result_t r;
    CHECK(ngfw_trie_lookup(t, "drive.google.com", &r) == 1, "exact lookup hits");
    CHECK(r.matched_exact == 1, "exact flag set");
    CHECK(r.confidence == 95, "confidence preserved (got %u)", r.confidence);
    CHECK(r.labels_matched == 3, "specificity = 3 labels (got %u)", r.labels_matched);

    CHECK(ngfw_trie_lookup(t, "www.netflix.com", &r) == 1, "suffix lookup hits");
    CHECK(r.matched_exact == 0, "suffix flag clear");
    CHECK(r.labels_matched == 2, "suffix specificity = 2 (got %u)", r.labels_matched);

    /* --- higher confidence wins a collision --- */
    ngfw_trie_insert(t, "netflix.com", APP_EVIL, 0, 1, 10, 0);
    CHECK(lookup_app(t, "netflix.com") == APP_NETFLIX,
          "lower-confidence duplicate must not displace the incumbent");
    ngfw_trie_insert(t, "netflix.com", APP_EVIL, 0, 1, 99, 0);
    CHECK(lookup_app(t, "netflix.com") == APP_EVIL,
          "higher-confidence duplicate must win");

    ngfw_trie_free(t);

    /* --- scale: many entries, verify no collisions lose data --- */
    ngfw_trie_t *big = ngfw_trie_new(5000);
    char buf[64];
    for (int i = 0; i < 5000; i++) {
        snprintf(buf, sizeof buf, "host%d.example%d.com", i, i % 97);
        ngfw_trie_insert(big, buf, (uint32_t)(1000 + i), 1, 1, 50, 0);
    }
    int lost = 0;
    for (int i = 0; i < 5000; i++) {
        snprintf(buf, sizeof buf, "host%d.example%d.com", i, i % 97);
        if (lookup_app(big, buf) != 1000 + i) lost++;
    }
    CHECK(lost == 0, "%d of 5000 entries lost after growth", lost);
    ngfw_trie_free(big);

    printf("  %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
