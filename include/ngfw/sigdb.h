/* On-disk signature database: position-independent, mmap'd read-only.
 *
 * Every internal reference is a byte offset from the start of the file, never a
 * pointer, so the blob can be mapped at any address and shared across processes
 * with no load-time fixups. */
#ifndef NGFW_SIGDB_H
#define NGFW_SIGDB_H

#include <stdint.h>
#include <stddef.h>

#define NGFW_SIGDB_MAGIC   0x4457474EU   /* "NGWD" little-endian */
#define NGFW_SIGDB_VERSION 3U

/* License tier of a signature's source, so a build can filter by what it may
 * ship. Ordered most-permissive first; a filter keeps everything <= its max. */
enum ngfw_license_tier {
    NGFW_LIC_PERMISSIVE = 0,   /* Apache-2.0 / MIT / BSD / self-derived */
    NGFW_LIC_LGPL       = 1,
    NGFW_LIC_GPL        = 2
};

/* Evidence strength. Tier A survives ECH; tier B does not. */
enum ngfw_tier { NGFW_TIER_A = 0, NGFW_TIER_B = 1, NGFW_TIER_C = 2, NGFW_TIER_D = 3 };

enum ngfw_domain_match { NGFW_DOM_SUFFIX = 0, NGFW_DOM_EXACT = 1 };

typedef struct {
    uint32_t magic;
    uint32_t format_version;
    uint32_t app_count;
    uint32_t domain_count;
    uint32_t string_pool_size;
    uint32_t app_offset;
    uint32_t domain_offset;
    uint32_t string_pool_offset;
    uint64_t built_at;
    uint32_t cidr_count;        /* added in format v2 */
    uint32_t cidr_offset;
    uint32_t payload_count;     /* added in format v3 */
    uint32_t payload_offset;
} ngfw_sigdb_header_t;

typedef struct {
    uint32_t app_id;
    uint32_t name_off;      /* offset into the string pool */
    uint16_t category;
    uint8_t  license_tier;  /* enum ngfw_license_tier */
    uint8_t  _pad;
} ngfw_sigdb_app_t;

/* An IP prefix. Tier C by nature: coarse, volatile, and wrong the moment the
 * host moves behind a CDN — so it narrows or corroborates, it does not decide. */
typedef struct {
    uint8_t  addr[16];      /* network byte order; IPv4 in the first 4 bytes */
    uint32_t app_id;
    uint8_t  prefix_len;
    uint8_t  af;            /* 4 or 6 */
    uint8_t  tier;
    uint8_t  confidence;
    uint8_t  license_tier;
    uint8_t  _pad[3];
} ngfw_sigdb_cidr_t;

/* A 4-byte payload prefix with a wildcard mask, matched at the start of a
 * flow's first payload-bearing segment.
 *
 * This is tier A: it reads the protocol on the wire rather than a name in a
 * header, so it survives Encrypted Client Hello, which will eventually blind
 * every SNI-based signature. libprotoident's insight is that four bytes in each
 * direction resolve a startling share of flows for almost no cost. */
typedef struct {
    uint8_t  value[4];
    uint8_t  mask[4];       /* 0xFF = byte must match, 0x00 = wildcard */
    uint32_t app_id;
    uint8_t  tier;
    uint8_t  confidence;
    uint8_t  license_tier;
    uint8_t  _pad;
} ngfw_sigdb_payload_t;

typedef struct {
    uint32_t name_off;      /* domain, stored forward: "www.netflix.com" */
    uint32_t app_id;
    uint8_t  match_type;    /* enum ngfw_domain_match */
    uint8_t  confidence;    /* 0-100 */
    uint8_t  tier;          /* enum ngfw_tier */
    uint8_t  license_tier;
} ngfw_sigdb_domain_t;

/* A loaded database. `base` is the mmap; the rest are derived views. */
typedef struct {
    const uint8_t             *base;
    size_t                     size;
    const ngfw_sigdb_header_t *hdr;
    const ngfw_sigdb_app_t    *apps;
    const ngfw_sigdb_domain_t *domains;
    const ngfw_sigdb_cidr_t   *cidrs;
    const ngfw_sigdb_payload_t *payloads;
    const char                *strings;
} ngfw_sigdb_t;

int         ngfw_sigdb_open(ngfw_sigdb_t *db, const char *path);
void        ngfw_sigdb_close(ngfw_sigdb_t *db);
const char *ngfw_sigdb_app_name(const ngfw_sigdb_t *db, uint32_t app_id);

#endif
