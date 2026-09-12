#include "ngfw/pcap.h"

#include <stdlib.h>
#include <string.h>

#define PCAP_MAGIC       0xA1B2C3D4U
#define PCAP_MAGIC_SWAP  0xD4C3B2A1U
#define PCAP_MAGIC_NS    0xA1B23C4DU
#define PCAP_MAGIC_NS_SW 0x4D3CB2A1U

#define MAX_SNAP (1u << 20)      /* 1 MB: refuse absurd caplens */

static uint8_t  g_buf[MAX_SNAP];

static uint32_t sw32(uint32_t v, int s)
{
    return s ? ((v >> 24) | ((v >> 8) & 0xFF00) | ((v << 8) & 0xFF0000) | (v << 24)) : v;
}

int ngfw_pcap_open(ngfw_pcap_t *p, const char *path)
{
    memset(p, 0, sizeof(*p));
    p->fp = fopen(path, "rb");
    if (!p->fp) return -1;

    uint8_t hdr[24];
    if (fread(hdr, 1, 24, p->fp) != 24) { fclose(p->fp); p->fp = NULL; return -1; }

    uint32_t magic;
    memcpy(&magic, hdr, 4);

    if (magic == PCAP_MAGIC)            { p->swapped = 0; p->nanosecond = 0; }
    else if (magic == PCAP_MAGIC_SWAP)  { p->swapped = 1; p->nanosecond = 0; }
    else if (magic == PCAP_MAGIC_NS)    { p->swapped = 0; p->nanosecond = 1; }
    else if (magic == PCAP_MAGIC_NS_SW) { p->swapped = 1; p->nanosecond = 1; }
    else { fclose(p->fp); p->fp = NULL; return -1; }   /* pcapng not supported */

    uint32_t snaplen, linktype;
    memcpy(&snaplen,  hdr + 16, 4);
    memcpy(&linktype, hdr + 20, 4);
    p->snaplen  = sw32(snaplen, p->swapped);
    p->linktype = sw32(linktype, p->swapped);
    return 0;
}

int ngfw_pcap_next(ngfw_pcap_t *p, ngfw_pcap_pkt_t *pkt)
{
    uint8_t rh[16];
    size_t n = fread(rh, 1, 16, p->fp);
    if (n == 0) return 0;
    if (n != 16) return -1;

    uint32_t v[4];
    memcpy(v, rh, 16);
    pkt->ts_sec  = sw32(v[0], p->swapped);
    pkt->ts_frac = sw32(v[1], p->swapped);
    pkt->caplen  = sw32(v[2], p->swapped);
    pkt->origlen = sw32(v[3], p->swapped);

    if (pkt->caplen > MAX_SNAP) return -1;
    if (fread(g_buf, 1, pkt->caplen, p->fp) != pkt->caplen) return -1;

    pkt->data = g_buf;
    return 1;
}

void ngfw_pcap_close(ngfw_pcap_t *p)
{
    if (p && p->fp) { fclose(p->fp); p->fp = NULL; }
}
