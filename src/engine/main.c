/* ngfw-classify — offline application classification over a pcap.
 *
 * Stage pipeline: decode -> flow lookup -> dissect -> field match -> verdict.
 * Once a verdict is final the fast path is flow lookup only; the matchers
 * never see more than the first few packets of a flow. */
#include "ngfw/decode.h"
#include "ngfw/flow.h"
#include "ngfw/lpm.h"
#include "ngfw/payload.h"
#include "ngfw/pcap.h"
#include "ngfw/sigdb.h"
#include "ngfw/trie.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Beyond this many packets a flow is given up on, so unclassifiable flows do
 * not hold matcher state forever. */
#define PACKET_BUDGET 12

typedef struct {
    uint64_t packets, decoded, undecodable;
    uint64_t tcp, udp;
    uint64_t client_hellos, sni_found, sni_matched, sni_unmatched;
    uint64_t ip_matched, payload_matched, master_only;
    uint64_t verdicts_provisional, verdicts_final, verdicts_revised;
} stats_t;

static const char *TIER_NAME[] = { "A", "B", "C", "D" };
static const char *LIC_NAME[]  = { "permissive", "LGPL", "GPL" };

static void ip_str(const uint8_t *ip, int version, char *out, size_t cap)
{
    if (version == 6) inet_ntop(AF_INET6, ip, out, (socklen_t)cap);
    else              inet_ntop(AF_INET,  ip, out, (socklen_t)cap);
}

/* Build the in-memory matcher from the mmap'd database. Prebuilding the trie
 * into the blob itself is a later optimisation; at this corpus size the build
 * costs milliseconds. */
static ngfw_trie_t *build_trie(const ngfw_sigdb_t *db, int max_license)
{
    ngfw_trie_t *t = ngfw_trie_new(db->hdr->domain_count);
    if (!t) return NULL;

    uint32_t added = 0, skipped = 0;
    for (uint32_t i = 0; i < db->hdr->domain_count; i++) {
        const ngfw_sigdb_domain_t *d = &db->domains[i];
        if (d->license_tier > max_license) { skipped++; continue; }
        if (d->name_off >= db->hdr->string_pool_size) continue;

        if (ngfw_trie_insert(t, db->strings + d->name_off, d->app_id,
                             d->match_type == NGFW_DOM_EXACT,
                             d->tier, d->confidence, d->license_tier) == 0)
            added++;
    }
    fprintf(stderr, "[sigdb] %u apps, %u domain rules loaded (%u skipped by "
                    "license filter), %zu trie nodes\n",
            db->hdr->app_count, added, skipped, ngfw_trie_node_count(t));
    return t;
}

/* Build the IP matchers. IPv4 and IPv6 get separate tries: mapping v4 into v6
 * would add 96 wasted levels to every v4 lookup, which is the common case. */
static int build_lpm(const ngfw_sigdb_t *db, int max_license,
                     ngfw_lpm_t **v4, ngfw_lpm_t **v6)
{
    *v4 = ngfw_lpm_new(32, db->hdr->cidr_count);
    *v6 = ngfw_lpm_new(128, db->hdr->cidr_count / 4 + 16);
    if (!*v4 || !*v6) return -1;

    uint32_t n4 = 0, n6 = 0, skipped = 0;
    for (uint32_t i = 0; i < db->hdr->cidr_count; i++) {
        const ngfw_sigdb_cidr_t *c = &db->cidrs[i];
        if (c->license_tier > max_license) { skipped++; continue; }

        ngfw_lpm_t *t = (c->af == 6) ? *v6 : *v4;
        if (ngfw_lpm_insert(t, c->addr, c->prefix_len, c->app_id,
                            c->tier, c->confidence, c->license_tier) == 0) {
            if (c->af == 6) n6++; else n4++;
        }
    }
    fprintf(stderr, "[sigdb] %u IPv4 + %u IPv6 prefixes loaded (%u skipped), "
                    "%zu/%zu trie nodes\n",
            n4, n6, skipped, ngfw_lpm_node_count(*v4), ngfw_lpm_node_count(*v6));
    return 0;
}

static ngfw_payload_set_t *build_payload(const ngfw_sigdb_t *db, int max_license)
{
    ngfw_payload_set_t *ps = ngfw_payload_new(db->hdr->payload_count);
    if (!ps) return NULL;

    uint32_t n = 0, skipped = 0;
    for (uint32_t i = 0; i < db->hdr->payload_count; i++) {
        const ngfw_sigdb_payload_t *q = &db->payloads[i];
        if (q->license_tier > max_license) { skipped++; continue; }
        if (ngfw_payload_insert(ps, q->value, q->mask, q->app_id, q->tier,
                                q->confidence, q->license_tier) == 0)
            n++;
    }
    fprintf(stderr, "[sigdb] %u payload prefixes loaded (%u skipped)\n", n, skipped);
    return ps;
}

/* Evidence fusion.
 *
 * A lower tier value is stronger evidence (A beats B beats C). New evidence is
 * taken when it is a stronger tier, or the same tier with higher confidence.
 * This is what stops a /12 cloud prefix from overriding a vendor-owned SNI —
 * the CDN case where naive engines confidently answer "AWS" for every site
 * hosted on it. */
static int evidence_is_better(const ngfw_verdict_t *v, uint8_t tier, uint8_t conf)
{
    if (v->app_id == NGFW_APP_UNKNOWN) return 1;
    if (tier < v->tier) return 1;
    if (tier == v->tier && conf > v->confidence) return 1;
    return 0;
}

static void emit(const ngfw_sigdb_t *db, const ngfw_packet_t *pkt,
                 const ngfw_flow_t *f, const char *sni, int final)
{
    char s[INET6_ADDRSTRLEN] = "?", d[INET6_ADDRSTRLEN] = "?";
    ip_str(pkt->src_ip, pkt->ip_version, s, sizeof s);
    ip_str(pkt->dst_ip, pkt->ip_version, d, sizeof d);

    const ngfw_verdict_t *v = &f->verdict;
    char proto[40] = "-";
    if (v->master_app_id != NGFW_APP_UNKNOWN)
        snprintf(proto, sizeof proto, "%s", ngfw_sigdb_app_name(db, v->master_app_id));

    /* With no app identity the app-verdict fields are unset, so report the
     * master protocol's tier and confidence instead of printing zeroes. */
    int have_app = (v->app_id != NGFW_APP_UNKNOWN);
    uint8_t tier = have_app ? v->tier : v->master_tier;
    uint8_t conf = have_app ? v->confidence : v->master_confidence;

    printf("%-9s %s:%u -> %s:%u  app=%-22s proto=%-12s tier=%s conf=%-3u %s  sni=%s\n",
           final ? "FINAL" : "provisional",
           s, pkt->src_port, d, pkt->dst_port,
           have_app ? ngfw_sigdb_app_name(db, v->app_id) : "unknown",
           proto,
           tier < 4 ? TIER_NAME[tier] : "?",
           conf,
           have_app ? (v->license_tier < 3 ? LIC_NAME[v->license_tier] : "?")
                    : "-",
           sni ? sni : "-");
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s [-l permissive|lgpl|gpl] [-q] <sigdb> <pcap>\n"
        "  -l  highest license tier to load (default: gpl = everything)\n"
        "  -q  summary only, no per-flow lines\n", p);
}

int main(int argc, char **argv)
{
    int max_license = NGFW_LIC_GPL, quiet = 0, argi = 1;

    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-l") && argi + 1 < argc) {
            const char *v = argv[++argi];
            if      (!strcmp(v, "permissive")) max_license = NGFW_LIC_PERMISSIVE;
            else if (!strcmp(v, "lgpl"))       max_license = NGFW_LIC_LGPL;
            else if (!strcmp(v, "gpl"))        max_license = NGFW_LIC_GPL;
            else { usage(argv[0]); return 2; }
        } else if (!strcmp(argv[argi], "-q")) {
            quiet = 1;
        } else {
            usage(argv[0]); return 2;
        }
        argi++;
    }
    if (argc - argi != 2) { usage(argv[0]); return 2; }

    ngfw_sigdb_t db;
    if (ngfw_sigdb_open(&db, argv[argi]) != 0) return 1;

    ngfw_trie_t *trie = build_trie(&db, max_license);
    if (!trie) { ngfw_sigdb_close(&db); return 1; }

    ngfw_payload_set_t *pset = build_payload(&db, max_license);

    ngfw_lpm_t *lpm4 = NULL, *lpm6 = NULL;
    if (build_lpm(&db, max_license, &lpm4, &lpm6) != 0) {
        fprintf(stderr, "error: cannot build IP matchers\n");
        ngfw_trie_free(trie); ngfw_sigdb_close(&db);
        return 1;
    }

    ngfw_pcap_t cap;
    if (ngfw_pcap_open(&cap, argv[argi + 1]) != 0) {
        fprintf(stderr, "error: cannot read pcap %s\n", argv[argi + 1]);
        ngfw_trie_free(trie); ngfw_sigdb_close(&db);
        return 1;
    }
    fprintf(stderr, "[pcap]  linktype=%u snaplen=%u\n\n", cap.linktype, cap.snaplen);

    ngfw_flow_table_t *ft = ngfw_flow_table_new(65536);
    stats_t st = {0};
    ngfw_pcap_pkt_t p;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int rc;
    while ((rc = ngfw_pcap_next(&cap, &p)) == 1) {
        st.packets++;

        ngfw_packet_t pk;
        if (ngfw_decode(p.data, p.caplen, cap.linktype, &pk) != 0) {
            st.undecodable++;
            continue;
        }
        st.decoded++;
        if (pk.l4proto == NGFW_L4_TCP) st.tcp++;
        else if (pk.l4proto == NGFW_L4_UDP) st.udp++;

        ngfw_flow_t *f = ngfw_flow_lookup(ft, &pk, NULL);
        f->packets++;

        if (f->verdict.is_final || f->packets > PACKET_BUDGET) continue;

        /* Stage: payload prefix -> the protocol on the wire.
         *
         * Deliberately fills master_app_id, never app_id directly. A TLS byte
         * pattern is durable evidence but says nothing about which application
         * is inside; answering "tls" for a Netflix flow would be a regression,
         * not a classification. */
        if (pset && !(f->verdict.evidence_mask & NGFW_EV_PAYLOAD) &&
            pk.payload && pk.payload_len >= 4) {
            ngfw_payload_result_t pr;
            if (ngfw_payload_lookup(pset, pk.payload, pk.payload_len, &pr)) {
                f->verdict.evidence_mask |= NGFW_EV_PAYLOAD;
                f->verdict.master_app_id = pr.app_id;
                f->verdict.master_tier = pr.tier;
                f->verdict.master_confidence = pr.confidence;
                st.payload_matched++;
                /* A protocol-only flow is still a classification worth
                 * reporting; without this a pure FTP or BitTorrent flow
                 * produces no output at all. */
                if (f->verdict.app_id == NGFW_APP_UNKNOWN) {
                    st.master_only++;
                    if (!quiet) emit(&db, &pk, f, NULL, 0);
                }
            }
        }

        /* Stage: IP/ASN attribution. Available on packet 1, cheap, and only
         * ever provisional — knowing who owns an address is not knowing which
         * application is using it. */
        if (!(f->verdict.evidence_mask & NGFW_EV_IP)) {
            ngfw_lpm_result_t ipr;
            const ngfw_lpm_t *t = (pk.ip_version == 6) ? lpm6 : lpm4;
            if (ngfw_lpm_lookup(t, pk.dst_ip, &ipr) ||
                ngfw_lpm_lookup(t, pk.src_ip, &ipr)) {
                st.ip_matched++;
                f->verdict.evidence_mask |= NGFW_EV_IP;
                if (evidence_is_better(&f->verdict, ipr.tier, ipr.confidence)) {
                    f->verdict.app_id = ipr.app_id;
                    f->verdict.tier = ipr.tier;
                    f->verdict.confidence = ipr.confidence;
                    f->verdict.license_tier = ipr.license_tier;
                    st.verdicts_provisional++;
                    if (!quiet) emit(&db, &pk, f, NULL, 0);
                }
            }
        }

        char sni[256];
        if (pk.l4proto == NGFW_L4_TCP && pk.payload && pk.payload_len > 0 &&
            ngfw_tls_sni(pk.payload, pk.payload_len, sni, sizeof sni)) {
            st.client_hellos++;
            st.sni_found++;

            ngfw_trie_result_t r;
            if (ngfw_trie_lookup(trie, sni, &r)) {
                f->verdict.evidence_mask |= NGFW_EV_SNI;
                if (evidence_is_better(&f->verdict, r.tier, r.confidence)) {
                    if (f->verdict.app_id != NGFW_APP_UNKNOWN &&
                        f->verdict.app_id != r.app_id)
                        st.verdicts_revised++;
                    f->verdict.app_id = r.app_id;
                    f->verdict.tier = r.tier;
                    f->verdict.confidence = r.confidence;
                    f->verdict.license_tier = r.license_tier;
                }
                /* An exact, vendor-owned name is as good as this tier gets. */
                f->verdict.is_final = (f->verdict.tier <= NGFW_TIER_B);
                st.sni_matched++;
                st.verdicts_final += f->verdict.is_final;
                if (!quiet) emit(&db, &pk, f, sni, f->verdict.is_final);
            } else {
                st.sni_unmatched++;
                /* An unmatched SNI does not erase weaker evidence already in
                 * hand: the flow may still be attributed by IP. Reporting
                 * "unknown" here would understate what the engine knows. */
                if (!quiet) {
                    if (f->verdict.app_id != NGFW_APP_UNKNOWN) {
                        emit(&db, &pk, f, sni, 0);
                    } else {
                        char s2[INET6_ADDRSTRLEN] = "?", d2[INET6_ADDRSTRLEN] = "?";
                        ip_str(pk.src_ip, pk.ip_version, s2, sizeof s2);
                        ip_str(pk.dst_ip, pk.ip_version, d2, sizeof d2);
                        printf("%-9s %s:%u -> %s:%u  app=%-22s tier=- conf=-   "
                               "-           sni=%s\n",
                               "nomatch", s2, pk.src_port, d2, pk.dst_port,
                               "unknown", sni);
                    }
                }
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

    printf("\n---- summary ----\n");
    printf("  packets            %llu (decoded %llu, undecodable %llu)\n",
           (unsigned long long)st.packets, (unsigned long long)st.decoded,
           (unsigned long long)st.undecodable);
    printf("  tcp / udp          %llu / %llu\n",
           (unsigned long long)st.tcp, (unsigned long long)st.udp);
    printf("  flows              %u (evictions %u)\n",
           ngfw_flow_count(ft), ngfw_flow_evictions(ft));
    printf("  TLS ClientHellos   %llu\n", (unsigned long long)st.client_hellos);
    printf("  SNI matched        %llu\n", (unsigned long long)st.sni_matched);
    printf("  SNI unmatched      %llu\n", (unsigned long long)st.sni_unmatched);
    printf("  IP/CIDR matched    %llu\n", (unsigned long long)st.ip_matched);
    printf("  payload matched    %llu (protocol/tier A)\n",
           (unsigned long long)st.payload_matched);
    printf("  protocol-only      %llu (no app identity, protocol known)\n",
           (unsigned long long)st.master_only);
    printf("  verdicts           %llu final, %llu provisional, %llu revised\n",
           (unsigned long long)st.verdicts_final,
           (unsigned long long)st.verdicts_provisional,
           (unsigned long long)st.verdicts_revised);
    printf("  elapsed            %.2f ms", ms);
    if (st.packets && ms > 0)
        printf("  (%.0f ns/packet)", ms * 1e6 / (double)st.packets);
    printf("\n");

    ngfw_flow_table_free(ft);
    ngfw_pcap_close(&cap);
    ngfw_trie_free(trie);
    ngfw_payload_free(pset);
    ngfw_lpm_free(lpm4);
    ngfw_lpm_free(lpm6);
    ngfw_sigdb_close(&db);
    return rc < 0 ? 1 : 0;
}
