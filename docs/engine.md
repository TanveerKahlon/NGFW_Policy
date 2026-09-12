# Signature validator

**Scope note:** this project collects application signatures. It is not a
firewall, and nothing here inspects or acts on live traffic.

This is the corpus's test harness. It compiles the collected signatures into a
database, replays synthetic flows against them, and reports what matched. That
answers the only question collection really has: *do these signatures actually
identify the thing they claim to?* Building it early meant the schema was
validated against a real packet before millions of rules were poured into it.

```bash
make check      # build, unit tests, compile sigdb, generate pcap, e2e assertions
make run        # classify the sample capture
```

No external dependencies. Plain `make`, C11, `clang` or `gcc`.

## Pipeline

```
pcap → decode → flow lookup → S0 IP/CIDR ─┐
        eth/ip/tcp   5-tuple   (packet 1)  ├→ fusion → verdict
                     └─ S1 TLS CH → SNI ───┘          revisable
                          (packet ~3)
```

Cheapest evidence first: the IP tier answers on packet 1, the SNI corrects it
when the ClientHello arrives.

Once a verdict is final the harness stops matching that flow — the matchers never
see more than the first `PACKET_BUDGET` (12) packets. That bound exists so the
validator behaves like a real consumer of the corpus would, not because anything
here runs inline.

| Stage | File |
|---|---|
| pcap reader (hand-rolled, no libpcap) | `src/engine/pcap.c` |
| Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP | `src/engine/decode.c` |
| TLS ClientHello → SNI | `src/engine/tls.c` |
| Flow table, revisable verdict | `src/engine/flow.c` |
| Reversed-label domain trie | `src/match/domain_trie.c` |
| LPM radix trie (IPv4 + IPv6 CIDR) | `src/match/lpm.c` |
| mmap'd signature database | `src/sigdb/sigdb_load.c` |

## Why a reversed-label trie, not Aho-Corasick

nDPI matches hostnames with an Aho-Corasick automaton. This engine walks
*labels* from the TLD inward instead, because domains are hierarchical label
sequences, not substrings.

The difference is not academic. Substring matching hits `netflix.com` inside
`notnetflix.com` and `netflix.com.evil.tld` unless every match is post-filtered
for label alignment — and that post-filter is exactly the bug class that
produces confident misattribution. The label trie cannot express the error:

```
notnetflix.com        → no match   (label is "notnetflix", not "netflix")
netflix.com.evil.tld  → no match   (walk starts at "tld")
www.netflix.com       → netflix    (suffix rule at the netflix.com node)
drive.google.com      → gsuite     (exact rule beats the shallower suffix)
x.drive.google.com    → google     (exact must not match deeper names)
```

Each node carries both an exact and a suffix verdict, so one walk resolves both
kinds. Exact beats suffix; the deepest suffix beats shallower ones. Cost is 3–5
hash probes per lookup, and insert/delete is trivial where an automaton would
need a full rebuild.

## Evidence fusion, and why the CDN case matters

Evidence carries a **tier**: A (protocol/byte, survives ECH), B (vendor-owned
name), C (IP/ASN ownership), D (port/heuristic). Stronger tier wins; equal tier
breaks on confidence.

This is not bookkeeping. An IP prefix tells you who owns an address, not which
application is talking — and behind a CDN those are wildly different answers.
Without tiering, every site fronted by CloudFront classifies as "aws":

```
provisional ... app=aws      tier=C conf=40                          (CloudFront prefix)
FINAL       ... app=netflix  tier=B conf=85  sni=www.netflix.com     (SNI corrects it)
```

Tier-C evidence is therefore **never final on its own** — it narrows or
corroborates. Cloud ranges get confidence 40; Tor exit nodes get 75, because
that attribution really is exact. Both facts are asserted in the test suite.

## Signature database

Position-independent, mmap'd read-only; every internal reference is a byte
offset, never a pointer, so the blob maps at any address and the page cache is
shared across processes. The loader bounds-checks every section against the
file size before use — a signature database is remotely-fetched data parsed by
a privileged process.

Compiled from the vendored corpora:

```bash
python3 tools/sigc.py --out build/ngfw.sigdb                          # everything
python3 tools/sigc.py --out build/permissive.sigdb --max-license permissive
```

### License filtering is checked at load time, not just at compile time

Every rule carries the licence it was harvested under, so the validator can be
asked what a redistributable build would actually cover:

```
$ ngfw-classify build/ngfw.sigdb capture.pcap
FINAL  ... app=zoom  tier=B conf=75  LGPL  sni=zoom.us

$ ngfw-classify -l permissive build/ngfw.sigdb capture.pcap
[sigdb] 241 apps, 3368 domain rules loaded (705 skipped by license filter)
nomatch ... app=unknown  sni=zoom.us
```

The same corpus, a different redistributable answer. This is the mechanism that
stops the collected app count from quietly becoming fiction.

## Verdicts are revisable

`ngfw_verdict_t` carries `is_final`. The callback fires more than once per flow:
a provisional answer as early as packet 1, corrected when better evidence
arrives (SNI is typically packet 3 of a TCP flow). This matters for collection
because it shows *which tier of evidence actually resolved an application* —
whether a name was needed, or an address alone was enough.

## Identity curation

An app count means nothing if the identities behind it are not distinct. Three
mechanisms keep it honest, in increasing order of human involvement:

**1. Separator-free identity key (automatic).** `epic-games` and `epicgames` are
one app. Sources disagree on separators — nDPI emits `AMAZON_VIDEO`, Netify
`amazon_video`, OpenAppID `"Amazon Video"` — and left alone that produced 54
near-duplicate groups. Identity is keyed on the punctuation-stripped form, which
is exact equality modulo separators, **not** fuzzy matching. Nothing merges on
name similarity; that is how "Amazon", "Amazon Music" and "Amazon Prime Video"
would wrongly collapse into one.

**2. `data/aliases.json` (human-reviewed).** Genuinely different spellings of one
service — `twitchtv` → `twitch`, `doh-dot` → `dns-over-https`. Each entry is
reviewed; the file explicitly excludes separator variants (handled by #1) and
parent/child granularity (`ebay` vs `ebay-search`), which are distinct rows
awaiting a hierarchy model.

**3. `data/drops.json` (human-reviewed).** Upstream rows that are not
applications, dropped **with a reason, never silently**. The current entry:
MMT-DPI groups government ccTLD labels (`.go.ke`, `.go.tz`, `.go.ug`, `.go.id`)
under one `PROTO_GO` id — Kenyan and Indonesian government sites, not an app.

`make audit` reports near-duplicate ids, suffixes claimed by several apps,
over-broad short suffixes, and whether every drop and alias is actually applied.
It runs as part of `make check`. Findings become curation entries; the tool
never auto-merges.

## Testing

Three layers, because they answer different questions:

| Layer | What it proves | Command |
|---|---|---|
| Trie unit tests (28) | label-boundary correctness, specificity, collisions, growth | `make test` |
| LPM unit tests (23) | longest-prefix wins, boundaries, /32 and /0, v6, growth | `make test` |
| Payload unit tests (18) | prefix-only matching, wildcards, tightest-wins, binary safety | `make test` |
| Duplicate audit | identities distinct, curation applied | `make audit` |
| Corpus round-trip | compiler and matcher agree on every rule | in `make check` |
| E2E assertions (19) | positives classify, negatives don't, license filter holds | `./tests/run_e2e.sh` |

The corpus round-trip is the highest-signal check available and needs no real
traffic: every domain the compiler emitted is replayed as a synthetic
ClientHello and must come back matched, with zero flow-table evictions.

**Current status:** full corpus round-trips with 0 evictions at ~354 ns/packet.
Database: **2,523 apps** / 10,272 domain / 30,383 CIDR / 466 payload rules
(1.22 MB). The permissive-only build keeps **582 apps** and every CIDR rule.

Synthesized flows validate the *matching path* exhaustively. They do **not**
validate that a signature is correct — that needs real traffic and is bounded
at a few hundred apps. Do not confuse the two.

## Two bugs the round-trip caught

1. **Flow-hash clustering.** 2,778 evictions at 3% table load. The FNV mix left
   low bits correlated with the ephemeral port, so sequential ports from one
   host piled into a few probe chains. Fixed with a splitmix64 finalizer →
   0 evictions. Real traffic has sequential ephemeral ports too, so this would
   have caused live misclassification.
2. **Leading-dot domains.** `.googlezip.net` — the conventional "and all
   subdomains" marker — produced an empty first label that no correct parser
   can match. Normalized in the compiler.

## Not yet implemented

- QUIC SNI (needs header-protection removal + AEAD of the CRYPTO frame);
  `ngfw_quic_sni()` exists as a stub so the call site is real
- JA3/JA4 — and when added they must default to `shared` / low confidence,
  since they identify TLS *stacks*, not applications
- Vectorscan regex tier (toolchain is now installed)
- Application hierarchy (`ebay` as parent of `ebay-search` / `ebay-watch`);
  479 shared suffixes are this, not duplication
- Prebuilt trie serialized into the blob; today it is built at load
- Live capture and hot reload — only if the corpus ever needs validating
  against real traffic rather than synthesized flows
