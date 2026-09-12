/* Unit tests for the masked 4-byte payload matcher. */
#include "ngfw/payload.h"

#include <stdio.h>
#include <string.h>

static int failures = 0, checks = 0;
#define CHECK(cond, ...) do {                          \
    checks++;                                          \
    if (!(cond)) {                                     \
        failures++;                                    \
        printf("  FAIL %s:%d  ", __FILE__, __LINE__);  \
        printf(__VA_ARGS__); printf("\n");             \
    }                                                  \
} while (0)

static const uint8_t FULL[4] = {0xFF,0xFF,0xFF,0xFF};

static int find(const ngfw_payload_set_t *p, const char *buf)
{
    ngfw_payload_result_t r;
    return ngfw_payload_lookup(p, (const uint8_t *)buf, (uint32_t)strlen(buf), &r)
           ? (int)r.app_id : -1;
}

int main(void)
{
    printf("payload matcher\n");
    ngfw_payload_set_t *p = ngfw_payload_new(32);

    ngfw_payload_insert(p, (const uint8_t *)"USER", FULL, 10, 0, 65, 0);
    ngfw_payload_insert(p, (const uint8_t *)"QUIT", FULL, 10, 0, 65, 0);
    ngfw_payload_insert(p, (const uint8_t *)"SSH-", FULL, 20, 0, 65, 0);

    CHECK(find(p, "USER anonymous")  == 10, "exact prefix matches past its end");
    CHECK(find(p, "QUIT\r\n")        == 10, "second pattern for the same app");
    CHECK(find(p, "SSH-2.0-OpenSSH") == 20, "distinct app matches");
    CHECK(find(p, "GET / HTTP/1.1")  == -1, "unknown prefix misses");
    CHECK(find(p, "USE")             == -1, "fewer than 4 bytes never matches");
    CHECK(find(p, "")                == -1, "empty payload never matches");

    /* Prefix semantics: only the FIRST four bytes are considered. */
    CHECK(find(p, "xUSER") == -1, "pattern must be at offset 0, not anywhere");

    /* --- wildcards --- */
    const uint8_t m_lo[4] = {0xFF,0xFF,0x00,0x00};
    ngfw_payload_insert(p, (const uint8_t *)"AB\0\0", m_lo, 30, 0, 50, 0);
    CHECK(find(p, "ABxy") == 30, "wildcard bytes are ignored");
    CHECK(find(p, "ABzz") == 30, "any value in wildcard position matches");
    CHECK(find(p, "ACxy") == -1, "a fixed byte must still match");

    /* A tighter pattern must beat a looser one covering the same bytes. */
    ngfw_payload_insert(p, (const uint8_t *)"ABcd", FULL, 31, 0, 50, 0);
    CHECK(find(p, "ABcd") == 31, "fully-specified beats wildcarded");
    CHECK(find(p, "ABce") == 30, "non-matching exact falls back to wildcard");

    /* An all-wildcard pattern would match everything and is refused. */
    const uint8_t none[4] = {0,0,0,0};
    int rc = ngfw_payload_insert(p, (const uint8_t *)"\0\0\0\0", none, 99, 0, 50, 0);
    CHECK(rc == -1, "all-wildcard insert is refused by the matcher itself");
    CHECK(find(p, "zzzz") == -1, "all-wildcard pattern must not match anything");

    /* Higher confidence wins a duplicate. */
    ngfw_payload_insert(p, (const uint8_t *)"DUPE", FULL, 40, 0, 30, 0);
    ngfw_payload_insert(p, (const uint8_t *)"DUPE", FULL, 41, 0, 10, 0);
    CHECK(find(p, "DUPExx") == 40, "lower-confidence duplicate ignored");
    ngfw_payload_insert(p, (const uint8_t *)"DUPE", FULL, 42, 0, 90, 0);
    CHECK(find(p, "DUPExx") == 42, "higher-confidence duplicate wins");

    /* Binary-safe: NUL bytes inside the pattern must work. */
    const uint8_t binpat[4] = {0x16, 0x00, 0x01, 0x00};
    ngfw_payload_insert(p, binpat, FULL, 50, 0, 60, 0);
    ngfw_payload_result_t r;
    CHECK(ngfw_payload_lookup(p, binpat, 4, &r) && r.app_id == 50,
          "NUL bytes inside a pattern are handled");

    ngfw_payload_free(p);

    /* Scale: growth must not lose entries. */
    ngfw_payload_set_t *big = ngfw_payload_new(4000);
    uint8_t v[4];
    for (int i = 0; i < 4000; i++) {
        v[0]=(uint8_t)(i&0xFF); v[1]=(uint8_t)((i>>8)&0xFF); v[2]=0xAA; v[3]=0x55;
        ngfw_payload_insert(big, v, FULL, (uint32_t)(1000+i), 0, 50, 0);
    }
    int lost = 0;
    for (int i = 0; i < 4000; i++) {
        v[0]=(uint8_t)(i&0xFF); v[1]=(uint8_t)((i>>8)&0xFF); v[2]=0xAA; v[3]=0x55;
        if (!ngfw_payload_lookup(big, v, 4, &r) || r.app_id != (uint32_t)(1000+i)) lost++;
    }
    CHECK(lost == 0, "%d of 4000 patterns lost after growth", lost);
    ngfw_payload_free(big);

    printf("  %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
