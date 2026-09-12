/* Unit tests for the LPM radix trie.
 *
 * Longest-prefix semantics are easy to get subtly wrong, and when they are
 * wrong the engine silently attributes traffic to the wrong owner. */
#include "ngfw/lpm.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int failures = 0, checks = 0;

#define CHECK(cond, ...) do {                          \
    checks++;                                          \
    if (!(cond)) {                                     \
        failures++;                                    \
        printf("  FAIL %s:%d  ", __FILE__, __LINE__);  \
        printf(__VA_ARGS__);                           \
        printf("\n");                                  \
    }                                                  \
} while (0)

static void v4(const char *s, uint8_t *out)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    memcpy(out, &a, 4);
}

static void v6(const char *s, uint8_t *out)
{
    struct in6_addr a;
    inet_pton(AF_INET6, s, &a);
    memcpy(out, &a, 16);
}

static int ins4(ngfw_lpm_t *l, const char *pfx, uint8_t plen, uint32_t app)
{
    uint8_t a[4];
    v4(pfx, a);
    return ngfw_lpm_insert(l, a, plen, app, 2, 40, 0);
}

static int find4(const ngfw_lpm_t *l, const char *ip)
{
    uint8_t a[4];
    ngfw_lpm_result_t r;
    v4(ip, a);
    return ngfw_lpm_lookup(l, a, &r) ? (int)r.app_id : -1;
}

int main(void)
{
    printf("lpm radix trie\n");

    ngfw_lpm_t *l = ngfw_lpm_new(32, 64);
    if (!l) { printf("  FAIL: allocation\n"); return 1; }

    ins4(l, "10.0.0.0",    8,  100);
    ins4(l, "10.1.0.0",   16,  200);
    ins4(l, "10.1.2.0",   24,  300);
    ins4(l, "192.168.0.0", 16, 400);

    /* --- longest prefix must win, not first or last inserted --- */
    CHECK(find4(l, "10.1.2.5")   == 300, "/24 must beat /16 and /8");
    CHECK(find4(l, "10.1.3.5")   == 200, "/16 must beat /8");
    CHECK(find4(l, "10.5.0.1")   == 100, "/8 matches when nothing deeper does");
    CHECK(find4(l, "192.168.1.1") == 400, "unrelated /16 matches");

    /* --- boundaries --- */
    CHECK(find4(l, "10.1.2.0")   == 300, "network address is inside the prefix");
    CHECK(find4(l, "10.1.2.255") == 300, "broadcast address is inside the prefix");
    CHECK(find4(l, "10.1.1.255") == 200, "one below the /24 falls back to /16");
    CHECK(find4(l, "10.1.3.0")   == 200, "one above the /24 falls back to /16");

    /* --- misses --- */
    CHECK(find4(l, "11.0.0.1")  == -1, "outside every prefix");
    CHECK(find4(l, "9.255.255.255") == -1, "just below 10/8");
    CHECK(find4(l, "172.16.0.1") == -1, "unrelated RFC1918 block");

    /* --- /32 host route beats everything --- */
    ins4(l, "10.1.2.7", 32, 999);
    CHECK(find4(l, "10.1.2.7") == 999, "/32 host route wins");
    CHECK(find4(l, "10.1.2.8") == 300, "neighbour still resolves to the /24");

    /* --- confidence resolves a duplicate prefix --- */
    uint8_t a[4];
    v4("10.9.0.0", a);
    ngfw_lpm_insert(l, a, 16, 501, 2, 30, 0);
    ngfw_lpm_insert(l, a, 16, 502, 2, 10, 0);       /* lower confidence: ignored */
    CHECK(find4(l, "10.9.1.1") == 501, "lower-confidence duplicate must not win");
    ngfw_lpm_insert(l, a, 16, 503, 2, 90, 0);       /* higher: takes over */
    CHECK(find4(l, "10.9.1.1") == 503, "higher-confidence duplicate must win");

    /* --- metadata round trip --- */
    ngfw_lpm_result_t r;
    v4("10.1.2.5", a);
    CHECK(ngfw_lpm_lookup(l, a, &r) == 1, "lookup hits");
    CHECK(r.prefix_len == 24, "prefix_len reported as specificity (got %u)", r.prefix_len);
    CHECK(r.tier == 2, "tier preserved");

    /* --- default route --- */
    ngfw_lpm_t *d = ngfw_lpm_new(32, 4);
    ins4(d, "0.0.0.0", 0, 7);
    CHECK(find4(d, "8.8.8.8") == 7, "0.0.0.0/0 matches everything");
    ngfw_lpm_free(d);

    ngfw_lpm_free(l);

    /* --- IPv6 --- */
    ngfw_lpm_t *l6 = ngfw_lpm_new(128, 16);
    uint8_t a6[16];
    v6("2606:4700::", a6);
    ngfw_lpm_insert(l6, a6, 32, 11, 2, 40, 0);
    v6("2606:4700:4700::", a6);
    ngfw_lpm_insert(l6, a6, 48, 22, 2, 40, 0);

    ngfw_lpm_result_t r6;
    v6("2606:4700:4700::1111", a6);
    CHECK(ngfw_lpm_lookup(l6, a6, &r6) && r6.app_id == 22, "v6 /48 beats /32");
    v6("2606:4700:9999::1", a6);
    CHECK(ngfw_lpm_lookup(l6, a6, &r6) && r6.app_id == 11, "v6 falls back to /32");
    v6("2001:db8::1", a6);
    CHECK(ngfw_lpm_lookup(l6, a6, &r6) == 0, "v6 miss returns 0");
    ngfw_lpm_free(l6);

    /* --- scale: many prefixes survive reallocation --- */
    ngfw_lpm_t *big = ngfw_lpm_new(32, 8000);
    char buf[32];
    for (int i = 0; i < 8000; i++) {
        snprintf(buf, sizeof buf, "%d.%d.%d.0", 20 + i / 65536, (i / 256) % 256, i % 256);
        ins4(big, buf, 24, (uint32_t)(5000 + i));
    }
    int lost = 0;
    for (int i = 0; i < 8000; i++) {
        snprintf(buf, sizeof buf, "%d.%d.%d.1", 20 + i / 65536, (i / 256) % 256, i % 256);
        if (find4(big, buf) != 5000 + i) lost++;
    }
    CHECK(lost == 0, "%d of 8000 prefixes lost after growth", lost);
    ngfw_lpm_free(big);

    printf("  %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
