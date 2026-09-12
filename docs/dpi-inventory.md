# DPI Source Inventory

**Phase A dossier** for the application-signature corpus.
Target: ≥3000 distinct identifiable applications.

**Scope:** this project collects and normalizes application signatures from
upstream corpora and public feeds. Building a firewall is not in scope; the C
code in this repo exists to validate that collected signatures match what they
claim to.

Every license and count below was verified against the repository or the file
itself on **2026-09-10**, not taken from documentation, blog posts or papers —
several of those proved wrong during this research (see *Corrections*).

Machine-readable companion: [`../data/sources.yaml`](../data/sources.yaml).

> **Status:** Phase A (dossier) and Phase B (vendoring + measurement) complete;
> the IP/CIDR derivation tier is now compiled into the engine, lifting the
> **permissive/shippable app count from 199 to 241** with 30,383 CIDR rules —
> all from public operator feeds, so no upstream corpus license attaches.
> **The validator is running** — collected signatures compile into a database and
> are replayed against synthetic flows end-to-end, filtered by the licence each
> rule was harvested under. See [`engine.md`](engine.md). It validated the schema
> against a real packet before any large-scale extraction, and caught two real
> bugs doing so.

---

## The core finding

**Application awareness is a data layer, not a dissector count.**

nDPI is the proof. Measured directly from the `dev` branch:

| Measure | Count |
|---|---|
| Protocol IDs defined in `ndpi_protocol_ids.h` | **495** |
| Documented protocols in `doc/protocols.rst` | **434** |
| Actual dissector `.c` files in `src/lib/protocols/` | **264** |
| Generated match data in `src/lib/inc_generated/` | **3.2 MB** |
| Hostname/SNI strings in `ndpi_content_match.c.inc` | **215 KB** |

More than 170 of nDPI's "protocols" have **no dedicated dissector at all**. They
are IDs attached to hostname, IP-prefix and ASN matching. The largest generated
tables are not protocols in any meaningful sense — they are attribution data:

```
866 KB  ndpi_icloud_private_relay_match      236 KB  ndpi_amazon_aws_match
580 KB  ndpi_nordvpn_match                   136 KB  ndpi_amazon_aws_ec2_match
312 KB  ndpi_azure_match                      96 KB  ndpi_tor_exit_nodes_match
305 KB  ndpi_tor_match                        86 KB  ndpi_digitalocean_match
```

Netify's corpus shows the same shape independently — **199 applications carrying
4,183 match rules** (3374 domain, 783 CIDR, 26 expression). A ratio of ~21 rules
per application.

The same holds for OpenAppID: 617 Lua detectors covering 564 applications, with
a 3,374-row *name registry* layered on top. Attribution data — not parsers — is
what scales an application count, and it is the only credible route to 3000.

---

## Tier 1 — Protocol dissection engines

| Project | License | Protocols | Lang | Status | Unique contribution |
|---|---|---|---|---|---|
| [nDPI](https://github.com/ntop/nDPI) | LGPL-3.0 | 495 IDs / 264 dissectors | C | Very active (daily) | Reference implementation; 3.2 MB attribution tables |
| [MMT-DPI](https://github.com/Montimage/mmt-dpi) | **Apache-2.0** | **682 defines** | C | Active | Permissive C engine; 5G/LTE (GTP, NAS, NGAP) |
| [Peafowl](https://github.com/DanieleDeSensi/peafowl) | **MIT** | L7 framework | C/C++ | Active | Permissive; multicore linear scalability |
| [libprotoident](https://github.com/LibtraceTeam/libprotoident) | **LGPL-3.0** | ~500 | C++ | Maintained | 4-byte classification — privacy-preserving |
| [Zeek](https://github.com/zeek/zeek) | BSD (LBNL/ICSI) | ~60 analyzers | C++ | Very active | Deep session semantics |
| [Spicy](https://github.com/zeek/spicy) | BSD | parser generator | C++ | Very active | **Compiles grammars AOT into C++ you link in** |
| [nfstream](https://github.com/nfstream/nfstream) | LGPL-3.0 | wraps nDPI | Python | Active | Flow-feature extraction reference |
| [junkie](https://github.com/rixed/junkie) | — | — | C | Low activity | Reference only |
| [go-dpi](https://github.com/mushorg/go-dpi) | MIT | wrappers | Go | **Dead (2022)** | Reference only |
| OpenDPI, L7-filter | GPL | — | C | Abandoned | Historical reference only |

## Tier 2 — Application signature corpora (the route to 3000)

| Source | License | Apps | Rules | Notes |
|---|---|---|---|---|
| **Snort OpenAppID ODP** | **GPL-2.0** ✅ verified in tarball | **564** | 617 Lua | Viral — unshippable in a proprietary build |
| **Netify `netify-apps.conf`** | **Apache-2.0** ✅ verified in file header | **199** | **4,183** | Cleanly reusable; format maps 1:1 to our schema |
| nDPI `inc_generated/` + `content_match` | LGPL-3.0 | — | 3.2 MB | IP/ASN/domain attribution tables |
| Suricata / ET Open rules | GPL-2.0 | — | many | Threat rules; some app fingerprinting |
| [Arkime](https://github.com/arkime/arkime) | **Apache-2.0** | — | — | JA4 fingerprinting + metadata model |
| Wireshark | GPL-2.0 | ~500 dissectors | — | Inline-unsuitable; reference only |

### Netify corpus structure (verified by download)

```
app:133:netify.netflix              → app table
dom:133:<domain>                    → rule, match_type=sni_suffix   (3374)
net:10119:2a12:e9c0::/29            → rule, match_type=ip_cidr6      (783)
nsd:-1:39:<base64 expression>       → rule, match_type=expression     (26)
```

Decoded `nsd` example: `app == 'netify.signal' && (other_port == 3478 || local_port == 3478)`

## Tier 3 — Live attribution feeds

Continuously refreshed; IP/ASN attribution decays fast.

| Feed | URL |
|---|---|
| AWS | `https://ip-ranges.amazonaws.com/ip-ranges.json` |
| GCP | `https://www.gstatic.com/ipranges/cloud.json` |
| Cloudflare | `https://www.cloudflare.com/ips-v4`, `/ips-v6` |
| Oracle | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` |
| Azure | service tags (download page) |
| Aggregator (60+ providers, daily) | `rezmoss/cloud-provider-ip-addresses` |
| Aggregator (unified) | `tobilg/public-cloud-provider-ip-ranges` |
| Tor exit nodes | Tor Project bulk exit list |
| VPN ranges | NordVPN, Mullvad, Surfshark (also inside nDPI) |
| BGP/ASN derivation | for entities publishing no feed |

Harvested by extending the existing crawler in this repo (`src/sources/`,
`src/outputs/`) — robots-aware, per-domain rate limited, DuckDB upsert.

## Tier 4 — Supporting infrastructure

| Project | License | Role |
|---|---|---|
| [Vectorscan](https://github.com/VectorCamp/vectorscan) | BSD (Intel) ✅ verified in LICENSE | SIMD multi-regex at line rate |
| [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) | Unlicense | Packet parsing, DPDK/AF_XDP wrappers |
| [libtins](https://github.com/mfontanini/libtins) | BSD-2 | Packet crafting/parsing |
| Aho-Corasick / LPM trie | various | Host-string and CIDR matching |

---

## Corrections to the original brief

1. **MMT-DPI is Apache-2.0** with **682 protocol defines** — more than nDPI, and
   permissively licensed. It was listed as a niche telecom option; it is
   arguably the strongest permissive dissection core available.
2. **Peafowl is MIT** — permissive, not a language-niche curiosity.
3. **libprotoident is LGPL-3.0, not GPL.** The 2017 relicensing request was
   granted. It is linkable without GPL obligations.
4. **Zeek + Spicy was missing entirely.** Spicy compiles protocol grammars
   ahead-of-time into C++ you link into your own binary, under BSD — the only
   permissive parser-generator path in existence.
5. **Vectorscan was missing.** L7-filter is described in the brief as having died
   from regex CPU cost; Vectorscan is the direct answer to that problem.
6. **go-dpi is dead** (last commit 2022) and is mostly nDPI/libprotoident
   wrappers — reference only, not an alternative.
7. **A permissive dissection core is achievable with zero GPL exposure**:
   MMT-DPI (Apache-2.0) + Peafowl (MIT) + Spicy (BSD) + Vectorscan (BSD).

---

## MEASURED results (Phase B complete, 2026-09-10)

All trees vendored at pinned commits and counted directly. Reproduce with
`scripts/vendor.sh` then `python3 tools/measure_corpus.py`.
Machine-readable: [`../data/corpus-measured.json`](../data/corpus-measured.json).

### Tier 1 — detector-backed applications (real matching logic exists)

| Source | License | Distinct apps | Unique to it | Extractable as data? |
|---|---|---|---|---|
| OpenAppID ODP | GPL-2.0 | **2,339** | **1,937** | ✅ 8,961 host patterns |
| MMT-DPI | **Apache-2.0** | 680 | 358 | ❌ **~20 domain strings only** |
| libprotoident | LGPL-3.0 | 511 | 359 | ⚠️ ~89 four-byte payload patterns |
| nDPI | LGPL-3.0 | 454 | 258 | ✅ 928 host + 48,635 CIDR |
| Netify | **Apache-2.0** | 198 | 76 | ✅ 4,183 rules |
| **Union, all sources** | | **3,495** | | **exceeds the 3000 target** |
| **Union, permissive-only** | | **823** | | ✅ **shippable** |

> **The "extractable as data" column is the one that matters, and it is where
> the naive reading goes wrong.** MMT-DPI has 680 protocol names but only ~20
> domain literals in its entire source — its detection logic is procedural C,
> not data. Extracting it would add 660 app *names* with no signatures behind
> them: taxonomy, not detection. Same for most of libprotoident, whose matching
> is 4-byte payload comparisons written as C expressions.
>
> Only OpenAppID, nDPI and Netify carry signatures extractable as data — and
> OpenAppID carries more than the other two combined.

### Tier 2 — name taxonomy (identity known, no signature)

ODP's `appMapping.data`: **2,489** flagged names, of which **1,820 are new**
relative to Tier 1. Worthless as signatures; valuable as a **derivation target
list** — known application identities to build our own signatures for.

### The ceiling

```
detector-backed today                 2,015   (823 shippable)
+ taxonomy names given signatures    +1,820
─────────────────────────────────────────────
ceiling                               3,835   >= 3000 target ✅
```

**3000 is reachable.** Not by collecting more libraries — the library well is
dry at ~2,015 — but by deriving signatures for the 1,820 already-named
identities, which is also the only license-clean route.

### Rule volume (a different question from app count)

| | rules |
|---|---|
| nDPI `inc_generated/` | 48,635 |
| nDPI `content_match` | 1,213 |
| Netify | 4,183 |
| **total** | **54,031** |

### Derivation feeds fetched (`data/feeds/`, all public/permissive)

| Feed | Identities | Prefixes |
|---|---|---|
| AWS `ip-ranges.json` | 28 services / 43 regions | 17,463 |
| GitHub `meta` | 14 | 7,356 |
| GCP `cloud.json` | 48 scopes | 1,102 |
| Oracle | 56 regions | 1,107 |
| DigitalOcean | — | 1,229 |
| Tor exit list | — | 1,336 |
| Cloudflare / Fastly | — | 41 |
| **Public Suffix List** | 10,325 rules | *(required for normalization)* |

**~29,600 permissively-licensed CIDRs**, replacing nDPI's 48,635 LGPL ones from
the *same upstream primaries* — fresher, and ours.

### Correction, then a correction to the correction

My first pass counted OpenAppID by `detection_name` in the Lua files, got **564**,
and concluded the "~2600" figure was inflated by ~78%. **That was wrong, and the
error was mine, not the vendor's.**

Most ODP apps have no dedicated Lua file. They appear as `appId` rows inside
shared `ssl_host_group_*.lua` and URL pattern tables — `{ 0, 4603, 'amp.dev' }`
— and an app with a host pattern is genuinely detectable whether or not it owns
a detector file. Measured properly:

| Measure | Count |
|---|---|
| `appMapping.data` rows | 3,374 |
| — all-zero flags (IANA service-name registry) | 880 |
| — flagged (ID allocations) | 2,494 |
| Named Lua detectors (`detection_name`) | 564 |
| **Host-pattern-backed apps** | **1,934** |
| **Distinct detectable identities** | **2,339** |

So the vendor's "~2600" was approximately right. Extractable signature yield:
**6,390 SSL host patterns + 2,571 URL host patterns**.

**2. nDPI's generated IP tables should be REGENERATED, not copied.** ✅ Verified:
nDPI ships the generator scripts in `utils/` —

```
aws_ip_addresses_download.sh      icloud_private_relay_ip_addresses_download.sh
azure_ip_addresses_download.sh    mullvad_ip_addresses_download.sh
cloudflare_ip_addresses_download.sh  google_cloud_ip_addresses_download.sh
akamai_ip_addresses_download.sh   asn_update.sh / get_routes_by_asn.sh
ipaddr2list.py                    mergeipaddrlist.py
```

Those 3.2 MB of tables are machine transformations of **public upstream feeds**.
Regenerating from the same primary sources under our own build converts an LGPL
entanglement into a **freshness advantage** — our tables are today's, nDPI's are
from whenever it last regenerated. This is the highest-leverage move available.

*(`ndpi_content_match.c.inc` is different — its hostname→protocol curation
involves editorial selection and is genuinely entangled. Reference only.)*

### The route to 3000+ is derivation, not aggregation

Not a Phase 5 afterthought — this is the only path past ~2,500 **and** the only
path to a permissively-licensed corpus:

- **Certificate Transparency logs** → SAN harvesting → per-org hostname sets.
  Public, free, unencumbered, enormous. Closest to how commercial vendors
  actually reach four digits.
- **Cloud/CDN/service IP feeds**, self-fetched (correction 2 above)
- **RIR delegated files + PeeringDB** → ASN → organization
- **Public Suffix List + domain rankings** → prioritization *(verify
  redistribution terms of whichever ranking is chosen)*
- **Mobile app-store metadata** → publisher → domains. Where the long tail
  lives, and the least-served area in open source.

Defensible claim: *"3,000+ applications, of which ~2,000 carry protocol- or
vendor-corroborated signatures and the remainder are domain-ownership-derived."*
A flat "3000 applications" is not.

## Open questions blocking the target

- ~~OpenAppID ODP licensing~~ — **RESOLVED, and the assumption was wrong.**
  There is no bespoke "Detector Content License Agreement". The tarball ships
  plain **GPL-2.0**, and each detector carries: *"proprietary Detector Content
  created by Cisco Systems... distributed under the GNU General Public License,
  v2... remains the property of Cisco."* Usable under GPLv2; **not shippable in
  a proprietary build.** Its 564 detectors are therefore research-tier only —
  which is why the permissive count (823) excludes them.
- **ECH is an existential threat to Tier B.** As Encrypted Client Hello deploys,
  plaintext SNI — the backbone of *every* open app-ID corpus including nDPI's and
  OpenAppID's — disappears. Optimising for raw app count optimises for the tier
  on a decay curve; Tier A (protocol behaviour) and Tier C (IP/ASN ownership)
  appreciate.
- **Toolchain gap (verified).** `cmake`, `ragel`, `autoconf`, `automake`,
  `pkg-config` are all absent — **Vectorscan cannot be built here today**.
  `sqlite3` 3.51.0 is present, which makes SQLite the obvious intermediate store.
  Sequence the regex tier after a cmake install rather than being surprised by it.
