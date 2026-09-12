/* Minimal pcap file reader.
 *
 * Hand-rolled rather than linked against libpcap: offline classification needs
 * ~100 lines of header parsing, and keeping it dependency-free means the engine
 * builds anywhere. Live capture will arrive behind this same interface. */
#ifndef NGFW_PCAP_H
#define NGFW_PCAP_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    FILE    *fp;
    uint32_t linktype;
    int      swapped;      /* file endianness differs from ours */
    int      nanosecond;
    uint32_t snaplen;
} ngfw_pcap_t;

typedef struct {
    uint32_t ts_sec, ts_frac;
    uint32_t caplen, origlen;
    const uint8_t *data;
} ngfw_pcap_pkt_t;

int  ngfw_pcap_open(ngfw_pcap_t *p, const char *path);
/* Returns 1 on a packet, 0 at EOF, -1 on error. `pkt->data` points into an
 * internal buffer valid until the next call. */
int  ngfw_pcap_next(ngfw_pcap_t *p, ngfw_pcap_pkt_t *pkt);
void ngfw_pcap_close(ngfw_pcap_t *p);

#endif
