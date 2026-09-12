#!/usr/bin/env bash
# End-to-end assertion: the engine must classify the positives and, more
# importantly, must NOT classify the label-boundary traps.
set -uo pipefail
cd "$(dirname "$0")/.."

BIN=build/ngfw-classify
DB=build/ngfw.sigdb
PCAP=tests/pcap/tls_sni.pcap
fail=0

out=$("$BIN" "$DB" "$PCAP" 2>/dev/null)

expect_app() {  # host, app
  if echo "$out" | grep -q "app=$2 .*sni=$1$"; then
    echo "  ok    $1 -> $2"
  else
    echo "  FAIL  $1 expected app=$2"; fail=1
  fi
}
expect_nomatch() {
  if echo "$out" | grep -q "^nomatch.*sni=$1$"; then
    echo "  ok    $1 -> correctly unclassified"
  else
    echo "  FAIL  $1 must NOT match (false positive!)"; fail=1
  fi
}

echo "positives"
expect_app www.netflix.com netflix
expect_app api.netflix.com netflix
expect_app drive.google.com gsuite
expect_app www.youtube.com youtube
expect_app github.com github

echo "negatives (label-boundary traps)"
expect_nomatch notnetflix.com
expect_nomatch netflix.com.evil.tld
expect_nomatch some-random-host.example

echo "license filtering"
perm=$("$BIN" -l permissive "$DB" "$PCAP" 2>/dev/null)
if echo "$perm" | grep -q "^nomatch.*sni=zoom.us$"; then
  echo "  ok    LGPL rule excluded from permissive build"
else
  echo "  FAIL  permissive build leaked an LGPL-derived rule"; fail=1
fi
# Assert the INTENT (a non-permissive rule exists and is excluded), not which
# source won the fusion - that legitimately changes as corpora are added.
if echo "$out" | grep -qE "^FINAL.*(LGPL|GPL).*sni=zoom.us$"; then
  echo "  ok    non-permissive rule present in full build"
else
  echo "  FAIL  full build lost the non-permissive rule"; fail=1
fi

# Evidence fusion: a vendor-owned SNI must beat a CDN/cloud IP attribution.
# Getting this backwards makes every site on CloudFront classify as "aws",
# which is the single most common way an IP tier ruins an engine.
echo "evidence fusion"
if [ -f build/fusion.pcap ]; then
  fz=$("$BIN" "$DB" build/fusion.pcap 2>/dev/null)
  if echo "$fz" | grep -q "^FINAL.*app=netflix .*sni=www.netflix.com"; then
    echo "  ok    SNI (tier B) overrides cloud IP (tier C)"
  else
    echo "  FAIL  SNI did not override the CDN IP attribution"; fail=1
  fi
  if echo "$fz" | grep -q "^provisional.*app=aws .*tier=C"; then
    echo "  ok    IP-only flow yields a provisional tier-C verdict"
  else
    echo "  FAIL  IP-only flow produced no tier-C attribution"; fail=1
  fi
  if echo "$fz" | grep -q "app=tor .*tier=C conf=75"; then
    echo "  ok    exact attribution (tor) carries higher confidence than CDN ranges"
  else
    echo "  FAIL  tor confidence not differentiated"; fail=1
  fi
  if echo "$fz" | grep -qE "^FINAL.*app=aws "; then
    echo "  FAIL  an IP-only attribution was marked FINAL"; fail=1
  else
    echo "  ok    tier-C evidence never becomes final on its own"
  fi
else
  echo "  skip  build/fusion.pcap not generated"
fi

# Tier A: protocol identification from payload bytes, and the trap that comes
# with it. Several corpora contain a four-byte TLS record header as one branch
# of a larger condition - libprotoident's taobao module, MMT-DPI's gnutella
# detector - and lifted out standalone each fires on every ClientHello in
# existence.
#
# Assert the PROPERTY, not the two names we happened to find first: this pcap is
# all TLS, so any tier-A protocol label on it is a false positive. Naming the
# offenders is what let the gnutella one through unnoticed.
echo "tier A protocol matching"
bogus=$(echo "$out" | grep -oE "proto=[a-z0-9-]+" | grep -v "proto=-" | sort -u)
if [ -n "$bogus" ]; then
  echo "  FAIL  TLS ClientHellos labelled by a payload pattern: $bogus"; fail=1
else
  echo "  ok    TLS ClientHellos carry no bogus protocol label"
fi
if [ -f build/proto.pcap ]; then
  pr=$("$BIN" "$DB" build/proto.pcap 2>/dev/null)
  if echo "$pr" | grep -q "proto=ftpcontrol"; then
    echo "  ok    real protocol magic still detected (FTP)"
  else
    echo "  FAIL  tier-A protocol detection stopped working"; fail=1
  fi
  if echo "$pr" | grep -qE "^provisional.*proto=ftpcontrol.*app=unknown|^provisional.*app=unknown.*proto=ftpcontrol"; then
    echo "  ok    protocol evidence fills proto, never the app slot"
  else
    echo "  FAIL  protocol evidence leaked into the application identity"; fail=1
  fi
else
  echo "  skip  build/proto.pcap not generated"
fi

# Full-corpus round trip: every domain the compiler emitted must be matched by
# the engine, with no flow-table eviction. Catches compiler/matcher drift and
# hash-clustering regressions without needing any real traffic.
echo "corpus round-trip"
if [ -f build/all_hosts.pcap ]; then
  rt=$("$BIN" -q "$DB" build/all_hosts.pcap 2>/dev/null)
  unmatched=$(echo "$rt" | awk '/SNI unmatched/{print $3}')
  evictions=$(echo "$rt" | awk '/flows /{gsub(/[()]/,"");print $4}')
  if [ "${unmatched:-1}" = "0" ]; then
    echo "  ok    every compiled domain matches"
  else
    echo "  FAIL  $unmatched compiled domains did not match"; fail=1
  fi
  if [ "${evictions:-1}" = "0" ]; then
    echo "  ok    no flow-table evictions"
  else
    echo "  FAIL  $evictions flow evictions - hash is clustering"; fail=1
  fi
else
  echo "  skip  build/all_hosts.pcap not generated"
fi

[ $fail -eq 0 ] && echo "e2e: PASS" || echo "e2e: FAIL"
exit $fail
