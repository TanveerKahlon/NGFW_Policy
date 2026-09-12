#!/usr/bin/env bash
# Derivation tier: fetch PRIMARY public feeds directly.
# These are the same upstreams nDPI's utils/*_download.sh scripts use, so the
# resulting tables are ours (no LGPL entanglement) AND fresher than nDPI's.
set -uo pipefail
OUT="$(cd "$(dirname "$0")/.." && pwd)/data/feeds"
mkdir -p "$OUT"

get() {
  local name="$1" url="$2"
  if curl -sSL --max-time 60 -o "$OUT/$name" "$url" 2>/dev/null; then
    printf "  %-26s %8s  %s\n" "$name" "$(du -h "$OUT/$name" | cut -f1)" "ok"
  else
    printf "  %-26s %8s  %s\n" "$name" "-" "FAILED"
  fi
}

echo "=== primary cloud/CDN feeds ==="
get aws-ip-ranges.json     "https://ip-ranges.amazonaws.com/ip-ranges.json"
get gcp-cloud.json         "https://www.gstatic.com/ipranges/cloud.json"
get gcp-goog.json          "https://www.gstatic.com/ipranges/goog.json"
get cloudflare-v4.txt      "https://www.cloudflare.com/ips-v4"
get cloudflare-v6.txt      "https://www.cloudflare.com/ips-v6"
get oracle-ip-ranges.json  "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
get digitalocean.csv       "https://digitalocean.com/geo/google.csv"
get github-meta.json       "https://api.github.com/meta"
get fastly-ip-list.json    "https://api.fastly.com/public-ip-list"
get tor-exit-list.txt      "https://check.torproject.org/torbulkexitlist"

echo "=== identity / normalization data ==="
get public_suffix_list.dat "https://publicsuffix.org/list/public_suffix_list.dat"
