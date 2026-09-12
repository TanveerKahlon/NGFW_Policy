#include "ngfw/decode.h"

#include <string.h>

/* Minimal TLS ClientHello parser, scoped to SNI extraction.
 *
 * Every field is length-checked against the captured buffer: a ClientHello is
 * the first attacker-controlled bytes of a flow, so a bounds slip here is
 * remotely triggerable. */

#define TLS_REC_HANDSHAKE   22
#define TLS_HS_CLIENT_HELLO 1
#define EXT_SERVER_NAME     0
#define SNI_TYPE_HOSTNAME   0

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

int ngfw_tls_sni(const uint8_t *buf, uint32_t len, char *sni, size_t sni_cap)
{
    if (!buf || len < 43 || sni_cap == 0) return 0;

    if (buf[0] != TLS_REC_HANDSHAKE) return 0;
    if (buf[1] != 0x03) return 0;                    /* TLS 1.x record version */

    uint32_t rec_len = rd16(buf + 3);
    uint32_t avail   = len - 5;
    if (rec_len > avail) rec_len = avail;            /* tolerate truncation */

    const uint8_t *p   = buf + 5;
    const uint8_t *end = p + rec_len;

    if (end - p < 4 || p[0] != TLS_HS_CLIENT_HELLO) return 0;
    uint32_t hs_len = rd24(p + 1);
    p += 4;
    if (hs_len < (uint32_t)(end - p)) end = p + hs_len;

    if (end - p < 34) return 0;
    p += 2 + 32;                                     /* client_version + random */

    if (end - p < 1) return 0;
    uint8_t sid = *p++;
    if (end - p < sid) return 0;
    p += sid;

    if (end - p < 2) return 0;
    uint16_t cs = rd16(p);
    p += 2;
    if (end - p < cs) return 0;
    p += cs;

    if (end - p < 1) return 0;
    uint8_t comp = *p++;
    if (end - p < comp) return 0;
    p += comp;

    if (end - p < 2) return 0;                       /* no extensions => no SNI */
    uint16_t ext_total = rd16(p);
    p += 2;
    if (ext_total > (uint16_t)(end - p)) ext_total = (uint16_t)(end - p);
    const uint8_t *ext_end = p + ext_total;

    while (ext_end - p >= 4) {
        uint16_t type = rd16(p);
        uint16_t elen = rd16(p + 2);
        p += 4;
        if (elen > (uint16_t)(ext_end - p)) return 0;

        if (type == EXT_SERVER_NAME) {
            const uint8_t *e = p, *e_end = p + elen;
            if (e_end - e < 2) return 0;
            uint16_t list_len = rd16(e);
            e += 2;
            if (list_len > (uint16_t)(e_end - e)) return 0;
            e_end = e + list_len;

            while (e_end - e >= 3) {
                uint8_t  nt = *e;
                uint16_t nl = rd16(e + 1);
                e += 3;
                if (nl > (uint16_t)(e_end - e)) return 0;
                if (nt == SNI_TYPE_HOSTNAME) {
                    size_t n = nl < sni_cap - 1 ? nl : sni_cap - 1;
                    memcpy(sni, e, n);
                    sni[n] = '\0';
                    /* Reject embedded NULs and obvious garbage. */
                    if (strlen(sni) != n || n == 0) return 0;
                    return 1;
                }
                e += nl;
            }
            return 0;
        }
        p += elen;
    }
    return 0;
}

int ngfw_quic_sni(const uint8_t *buf, uint32_t len, char *sni, size_t sni_cap)
{
    (void)buf; (void)len; (void)sni; (void)sni_cap;
    return 0;   /* needs header-protection removal + AEAD; see M5 */
}
